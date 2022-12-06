//===- UnsafeBufferUsage.cpp - Replace pointers with modern C++ -----------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "clang/Analysis/Analyses/UnsafeBufferUsage.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "llvm/ADT/SmallVector.h"

using namespace llvm;
using namespace clang;
using namespace ast_matchers;

namespace clang::ast_matchers::internal {
// A `RecursiveASTVisitor` that traverses all descendants of a given node "n"
// except for those belonging to a different callable of "n".
class MatchDescendantVisitor
    : public RecursiveASTVisitor<MatchDescendantVisitor> {
public:
  typedef RecursiveASTVisitor<MatchDescendantVisitor> VisitorBase;

  // Creates an AST visitor that matches `Matcher` on all
  // descendants of a given node "n" except for the ones
  // belonging to a different callable of "n".
  MatchDescendantVisitor(const DynTypedMatcher *Matcher, ASTMatchFinder *Finder,
                         BoundNodesTreeBuilder *Builder,
                         ASTMatchFinder::BindKind Bind)
      : Matcher(Matcher), Finder(Finder), Builder(Builder), Bind(Bind),
        Matches(false) {}

  // Returns true if a match is found in a subtree of `DynNode`, which belongs
  // to the same callable of `DynNode`.
  bool findMatch(const DynTypedNode &DynNode) {
    Matches = false;
    if (const Stmt *StmtNode = DynNode.get<Stmt>()) {
      TraverseStmt(const_cast<Stmt *>(StmtNode));
      *Builder = ResultBindings;
      return Matches;
    }
    return false;
  }

  // The following are overriding methods from the base visitor class.
  // They are public only to allow CRTP to work. They are *not *part
  // of the public API of this class.

  // For the matchers so far used in spanification, we only need to match
  // `Stmt`s.  To override more as needed.

  bool TraverseDecl(Decl *Node) {
    if (!Node)
      return true;
    if (!match(*Node))
      return false;
    // To skip callables:
    if (llvm::isa<FunctionDecl, BlockDecl, ObjCMethodDecl>(Node))
      return true;
    // Traverse descendants
    return VisitorBase::TraverseDecl(Node);
  }

  bool TraverseStmt(Stmt *Node, DataRecursionQueue *Queue = nullptr) {
    if (!Node)
      return true;
    if (!match(*Node))
      return false;
    // To skip callables:
    if (llvm::isa<LambdaExpr>(Node))
      return true;
    return VisitorBase::TraverseStmt(Node);
  }

  bool shouldVisitTemplateInstantiations() const { return true; }
  bool shouldVisitImplicitCode() const {
    // TODO: let's ignore implicit code for now
    return false;
  }

private:
  // Sets 'Matched' to true if 'Matcher' matches 'Node'
  //
  // Returns 'true' if traversal should continue after this function
  // returns, i.e. if no match is found or 'Bind' is 'BK_All'.
  template <typename T> bool match(const T &Node) {
    BoundNodesTreeBuilder RecursiveBuilder(*Builder);

    if (Matcher->matches(DynTypedNode::create(Node), Finder,
                         &RecursiveBuilder)) {
      ResultBindings.addMatch(RecursiveBuilder);
      Matches = true;
      if (Bind != ASTMatchFinder::BK_All)
        return false; // Abort as soon as a match is found.
    }
    return true;
  }

  const DynTypedMatcher *const Matcher;
  ASTMatchFinder *const Finder;
  BoundNodesTreeBuilder *const Builder;
  BoundNodesTreeBuilder ResultBindings;
  const ASTMatchFinder::BindKind Bind;
  bool Matches;
};

AST_MATCHER_P(Stmt, forEveryDescendant, Matcher<Stmt>, innerMatcher) {
  MatchDescendantVisitor Visitor(new DynTypedMatcher(innerMatcher), Finder,
                                 Builder, ASTMatchFinder::BK_All);
  return Visitor.findMatch(DynTypedNode::create(Node));
}
} // namespace clang::ast_matchers::internal

namespace {
// Because the analysis revolves around variables and their types, we'll need to
// track uses of variables (aka DeclRefExprs).
using DeclUseList = SmallVector<const DeclRefExpr *, 1>;

// Convenience typedef.
using FixItList = UnsafeBufferUsageHandler::FixItList;

// Defined below.
class Strategy;
} // namespace

// Because we're dealing with raw pointers, let's define what we mean by that.
static auto hasPointerType() {
  return anyOf(
    hasType(pointerType()),
    hasType(autoType(
            hasDeducedType(hasUnqualifiedDesugaredType(pointerType())))),
    // DecayedType, e.g., array type in formal parameter decl
    hasType(decayedType(hasDecayedType(pointerType()))),
    // ElaboratedType, e.g., typedef
    hasType(elaboratedType(hasUnqualifiedDesugaredType(pointerType()))),
    // template instantiated types
    hasType(substTemplateTypeParmType(hasReplacementType(pointerType()))));
}

namespace {
/// Gadget is an individual operation in the code that may be of interest to
/// this analysis. Each (non-abstract) subclass corresponds to a specific
/// rigid AST structure that constitutes an operation on a pointer-type object.
/// Discovery of a gadget in the code corresponds to claiming that we understand
/// what this part of code is doing well enough to potentially improve it.
/// Gadgets can be unsafe (immediately deserving a warning) or safe (not
/// deserving a warning per se, but affecting our decision-making process
/// nonetheless).
class Gadget {
public:
  enum class Kind {
#define GADGET(x) x,
#include "clang/Analysis/Analyses/UnsafeBufferUsageGadgets.def"
#undef GADGETS
  };

  /// Determine if a kind is a safe kind. Slower than calling isSafe().
  static bool isSafeKind(Kind K) {
    switch (K) {
#define UNSAFE_GADGET(x)                                                       \
    case Kind::x:
#include "clang/Analysis/Analyses/UnsafeBufferUsageGadgets.def"
#undef UNSAFE_GADGET
      return false;

#define SAFE_GADGET(x)                                                         \
    case Kind::x:
#include "clang/Analysis/Analyses/UnsafeBufferUsageGadgets.def"
#undef SAFE_GADGET
      return true;
    }
    llvm_unreachable("Invalid gadget kind!");
  }

  /// Common type of ASTMatchers used for discovering gadgets.
  /// Useful for implementing the static matcher() methods
  /// that are expected from all non-abstract subclasses.
  using Matcher = decltype(stmt());

  Gadget(Kind K) : K(K) {}

  Kind getKind() const { return K; }

  virtual bool isSafe() const = 0;
  virtual const Stmt *getBaseStmt() const = 0;

  /// Returns the list of pointer-type variables on which this gadget performs
  /// its operation. Typically there's only one variable. This isn't a list
  /// of all DeclRefExprs in the gadget's AST!
  virtual DeclUseList getClaimedVarUseSites() const = 0;

  /// Returns a fixit that would fix the current gadget according to
  /// the current strategy. Returns None if the fix cannot be produced;
  /// returns an empty list if no fixes are necessary.
  virtual Optional<FixItList> getFixits(const Strategy &) const {
    return None;
  }

  virtual ~Gadget() {}

private:
  Kind K;
};

using GadgetList = std::vector<std::unique_ptr<Gadget>>;

/// Unsafe gadgets correspond to unsafe code patterns that warrants
/// an immediate warning.
class UnsafeGadget : public Gadget {
public:
  UnsafeGadget(Kind K) : Gadget(K) {
    assert(classof(this) && "Invalid unsafe gadget kind!");
  }

  static bool classof(const Gadget *G) { return !isSafeKind(G->getKind()); }
  bool isSafe() const override { return false; }
};

/// Safe gadgets correspond to code patterns that aren't unsafe but need to be
/// properly recognized in order to emit correct warnings and fixes over unsafe
/// gadgets. For example, if a raw pointer-type variable is replaced by
/// a safe C++ container, every use of such variable may need to be
/// carefully considered and possibly updated.
class SafeGadget : public Gadget {
public:
  SafeGadget(Kind K) : Gadget(K) {
    assert(classof(this) && "Invalid safe gadget kind!");
  }

  static bool classof(const Gadget *G) { return isSafeKind(G->getKind()); }
  bool isSafe() const override { return true; }
};

/// An increment of a pointer-type value is unsafe as it may run the pointer
/// out of bounds.
class IncrementGadget : public UnsafeGadget {
  const UnaryOperator *Op;

public:
  IncrementGadget(const MatchFinder::MatchResult &Result)
      : UnsafeGadget(Kind::Increment),
        Op(Result.Nodes.getNodeAs<UnaryOperator>("op")) {}

  static bool classof(const Gadget *G) {
    return G->getKind() == Kind::Increment;
  }

  static Matcher matcher() {
    return stmt(unaryOperator(
      hasOperatorName("++"),
      hasUnaryOperand(ignoringParenImpCasts(hasPointerType()))
    ).bind("op"));
  }

  const Stmt *getBaseStmt() const override { return Op; }

  DeclUseList getClaimedVarUseSites() const override {
    if (const auto *DRE =
            dyn_cast<DeclRefExpr>(Op->getSubExpr()->IgnoreParenImpCasts())) {
      return {DRE};
    }

    return {};
  }
};

/// A decrement of a pointer-type value is unsafe as it may run the pointer
/// out of bounds.
class DecrementGadget : public UnsafeGadget {
  const UnaryOperator *Op;

public:
  DecrementGadget(const MatchFinder::MatchResult &Result)
      : UnsafeGadget(Kind::Decrement),
        Op(Result.Nodes.getNodeAs<UnaryOperator>("op")) {}

  static bool classof(const Gadget *G) {
    return G->getKind() == Kind::Decrement;
  }

  static Matcher matcher() {
    return stmt(unaryOperator(
      hasOperatorName("--"),
      hasUnaryOperand(ignoringParenImpCasts(hasPointerType()))
    ).bind("op"));
  }

  const Stmt *getBaseStmt() const override { return Op; }

  DeclUseList getClaimedVarUseSites() const override {
    if (const auto *DRE =
            dyn_cast<DeclRefExpr>(Op->getSubExpr()->IgnoreParenImpCasts())) {
      return {DRE};
    }

    return {};
  }
};

/// Array subscript expressions on raw pointers as if they're arrays. Unsafe as
/// it doesn't have any bounds checks for the array.
class ArraySubscriptGadget : public UnsafeGadget {
  const ArraySubscriptExpr *ASE;

public:
  ArraySubscriptGadget(const MatchFinder::MatchResult &Result)
      : UnsafeGadget(Kind::ArraySubscript),
        ASE(Result.Nodes.getNodeAs<ArraySubscriptExpr>("arraySubscr")) {}

  static bool classof(const Gadget *G) {
    return G->getKind() == Kind::ArraySubscript;
  }

  static Matcher matcher() {
    return stmt(
        arraySubscriptExpr(hasBase(ignoringParenImpCasts(hasPointerType())),
                           unless(hasIndex(integerLiteral(equals(0)))))
            .bind("arraySubscr"));
  }

  const Stmt *getBaseStmt() const override { return ASE; }

  DeclUseList getClaimedVarUseSites() const override {
    if (const auto *DRE =
            dyn_cast<DeclRefExpr>(ASE->getBase()->IgnoreParenImpCasts())) {
      return {DRE};
    }

    return {};
  }
};

/// A call of a function or method that performs unchecked buffer operations
/// over one of its pointer parameters.
class UnsafeBufferUsageAttrGadget : public UnsafeGadget {
    const CallExpr *Op;

public:
    UnsafeBufferUsageAttrGadget(const MatchFinder::MatchResult &Result)
      : UnsafeGadget(Kind::UnsafeBufferUsageAttr),
        Op(Result.Nodes.getNodeAs<CallExpr>("call_expr")) {}

  static bool classof(const Gadget *G) {
    return G->getKind() == Kind::UnsafeBufferUsageAttr;
  }

  static Matcher matcher() {
    return stmt(callExpr(callee(functionDecl(hasAttr(attr::UnsafeBufferUsage))))
                          .bind("call_expr"));
  }

  const Stmt *getBaseStmt() const override { return Op; }

  DeclUseList getClaimedVarUseSites() const override {
    // FIXME: Not implemented yet. Returning {} is safe as it causes the gadget
    // to block any attempts to fix variables that it could have otherwise
    // claimed as known.
    return {};
  }
};
} // namespace

namespace {
// An auxiliary tracking facility for the fixit analysis. It helps connect
// declarations to its and make sure we've covered all uses with our analysis
// before we try to fix the declaration.
class DeclUseTracker {
  using UseSetTy = SmallSet<const DeclRefExpr *, 16>;
  using DefMapTy = DenseMap<const VarDecl *, const DeclStmt *>;

  // Allocate on the heap for easier move.
  std::unique_ptr<UseSetTy> Uses{std::make_unique<UseSetTy>()};
  DefMapTy Defs{};

public:
  DeclUseTracker() = default;
  DeclUseTracker(const DeclUseTracker &) = delete; // Let's avoid copies.
  DeclUseTracker(DeclUseTracker &&) = default;

  // Start tracking a freshly discovered DRE.
  void discoverUse(const DeclRefExpr *DRE) { Uses->insert(DRE); }

  // Stop tracking the DRE as it's been fully figured out.
  void claimUse(const DeclRefExpr *DRE) {
    assert(Uses->count(DRE) &&
           "DRE not found or claimed by multiple matchers!");
    Uses->erase(DRE);
  }

  // A variable is unclaimed if at least one use is unclaimed.
  bool hasUnclaimedUses(const VarDecl *VD) const {
    // FIXME: Can this be less linear? Maybe maintain a map from VDs to DREs?
    return any_of(*Uses, [VD](const DeclRefExpr *DRE) {
      return DRE->getDecl()->getCanonicalDecl() == VD->getCanonicalDecl();
    });
  }

  void discoverDecl(const DeclStmt *DS) {
    for (const Decl *D: DS->decls()) {
      if (const auto *VD = dyn_cast<VarDecl>(D)) {
        assert(Defs.count(VD) == 0 && "Definition already discovered!");
        Defs[VD] = DS;
      }
    }
  }

  const DeclStmt *lookupDecl(const VarDecl *VD) const {
    auto It = Defs.find(VD);
    assert(It != Defs.end() && "Definition never discovered!");
    return It->second;
  }
};
} // namespace

namespace {
// Strategy is a map from variables to the way we plan to emit fixes for
// these variables. It is figured out gradually by trying different fixes
// for different variables depending on gadgets in which these variables
// participate.
class Strategy {
public:
  enum class Kind {
    Wontfix,    // We don't plan to emit a fixit for this variable.
    Span,       // We recommend replacing the variable with std::span.
    Iterator,   // We recommend replacing the variable with std::span::iterator.
    Array,      // We recommend replacing the variable with std::array.
    Vector      // We recommend replacing the variable with std::vector.
  };

private:
  using MapTy = llvm::DenseMap<const VarDecl *, Kind>;

  MapTy Map;

public:
  Strategy() = default;
  Strategy(const Strategy &) = delete; // Let's avoid copies.
  Strategy(Strategy &&) = default;

  void set(const VarDecl *VD, Kind K) {
    Map[VD] = K;
  }

  Kind lookup(const VarDecl *VD) const {
    auto I = Map.find(VD);
    if (I == Map.end())
      return Kind::Wontfix;

    return I->second;
  }
};
} // namespace

/// Scan the function and return a list of gadgets found with provided kits.
static std::pair<GadgetList, DeclUseTracker> findGadgets(const Decl *D) {

  struct GadgetFinderCallback : MatchFinder::MatchCallback {
    GadgetList Gadgets;
    DeclUseTracker Tracker;

    void run(const MatchFinder::MatchResult &Result) override {
      if (const auto *DRE = Result.Nodes.getNodeAs<DeclRefExpr>("any_dre")) {
        Tracker.discoverUse(DRE);
      }

      if (const auto *DS = Result.Nodes.getNodeAs<DeclStmt>("any_ds")) {
        Tracker.discoverDecl(DS);
      }

      // Figure out which matcher we've found, and call the appropriate
      // subclass constructor.
      // FIXME: Can we do this more logarithmically?
#define GADGET(x)                                                              \
      if (Result.Nodes.getNodeAs<Stmt>(#x)) {                                  \
        Gadgets.push_back(std::make_unique<x ## Gadget>(Result));              \
        return;                                                                \
      }
#include "clang/Analysis/Analyses/UnsafeBufferUsageGadgets.def"
#undef GADGET
    }
  };

  MatchFinder M;
  GadgetFinderCallback CB;

  // clang-format off
  M.addMatcher(
    stmt(forEveryDescendant(
      stmt(anyOf(
        // Add Gadget::matcher() for every gadget in the registry.
#define GADGET(x)                                                              \
        x ## Gadget::matcher().bind(#x),
#include "clang/Analysis/Analyses/UnsafeBufferUsageGadgets.def"
#undef GADGET
        // In parallel, match all DeclRefExprs so that to find out
        // whether there are any uncovered by gadgets.
        declRefExpr(hasPointerType(), to(varDecl())).bind("any_dre"),
        // Also match DeclStmts because we'll need them when fixing
        // their underlying VarDecls that otherwise don't have
        // any backreferences to DeclStmts.
        declStmt().bind("any_ds")
      ))
      // FIXME: Idiomatically there should be a forCallable(equalsNode(D))
      // here, to make sure that the statement actually belongs to the
      // function and not to a nested function. However, forCallable uses
      // ParentMap which can't be used before the AST is fully constructed.
      // The original problem doesn't sound like it needs ParentMap though,
      // maybe there's a more direct solution?
    )),
    &CB
  );
  // clang-format on

  M.match(*D->getBody(), D->getASTContext());

  // Gadgets "claim" variables they're responsible for. Once this loop finishes,
  // the tracker will only track DREs that weren't claimed by any gadgets,
  // i.e. not understood by the analysis.
  for (const auto &G : CB.Gadgets) {
    for (const auto *DRE : G->getClaimedVarUseSites()) {
      CB.Tracker.claimUse(DRE);
    }
  }

  return {std::move(CB.Gadgets), std::move(CB.Tracker)};
}

void clang::checkUnsafeBufferUsage(const Decl *D,
                                   UnsafeBufferUsageHandler &Handler) {
  assert(D && D->getBody());

  SmallSet<const VarDecl *, 8> WarnedDecls;

  auto [Gadgets, Tracker] = findGadgets(D);

  DenseMap<const VarDecl *, std::vector<const Gadget *>> Map;

  // First, let's sort gadgets by variables. If some gadgets cover more than one
  // variable, they'll appear more than once in the map.
  for (const auto &G : Gadgets) {
    DeclUseList DREs = G->getClaimedVarUseSites();

    // Populate the map.
    bool Pushed = false;
    for (const DeclRefExpr *DRE : DREs) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        Map[VD].push_back(G.get());
        Pushed = true;
      }
    }

    if (!Pushed && !G->isSafe()) {
      // We won't return to this gadget later. Emit the warning right away.
      Handler.handleUnsafeOperation(G->getBaseStmt());
      continue;
    }
  }

  Strategy S;

  for (const auto &Item : Map) {
    const VarDecl *VD = Item.first;
    const std::vector<const Gadget *> &VDGadgets = Item.second;

    // If the variable has no unsafe gadgets, skip it entirely.
    if (!any_of(VDGadgets, [](const Gadget *G) { return !G->isSafe(); }))
      continue;

    Optional<FixItList> Fixes = None;

    // Avoid suggesting fixes if not all uses of the variable are identified
    // as known gadgets.
    // FIXME: Support parameter variables as well.
    if (!Tracker.hasUnclaimedUses(VD) && VD->isLocalVarDecl()) {
      // Choose the appropriate strategy. FIXME: We should try different
      // strategies.
      S.set(VD, Strategy::Kind::Span);

      // Check if it works.
      // FIXME: This isn't sufficient (or even correct) when a gadget has
      // already produced a fixit for a different variable i.e. it was mentioned
      // in the map twice (or more). In such case the correct thing to do is
      // to undo the previous fix first, and then if we can't produce the new
      // fix for both variables, revert to the old one.
      Fixes = FixItList{};
      for (const Gadget *G : VDGadgets) {
        Optional<FixItList> F = G->getFixits(S);
        if (!F) {
          Fixes = None;
          break;
        }

        for (auto &&Fixit: *F)
          Fixes->push_back(std::move(Fixit));
      }
    }

    if (Fixes) {
      // If we reach this point, the strategy is applicable.
      Handler.handleFixableVariable(VD, std::move(*Fixes));
    } else {
      // The strategy has failed. Emit the warning without the fixit.
      S.set(VD, Strategy::Kind::Wontfix);
      for (const Gadget *G : VDGadgets) {
        if (!G->isSafe()) {
          Handler.handleUnsafeOperation(G->getBaseStmt());
        }
      }
    }
  }
}
