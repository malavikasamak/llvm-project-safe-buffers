; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --version 5
; RUN: opt -S -passes='print<scalar-evolution>,loop-mssa(licm,loop-simplifycfg,loop-predication)' -verify-scev < %s 2>/dev/null | FileCheck %s

; Make sure we don't assert due to insufficient SCEV invalidation.

define i64 @"main"(ptr addrspace(1) %p, i1 %check) {
; CHECK-LABEL: define i64 @main(
; CHECK-SAME: ptr addrspace(1) [[P:%.*]], i1 [[CHECK:%.*]]) {
; CHECK-NEXT:  [[ENTRY:.*:]]
; CHECK-NEXT:    switch i32 0, label %[[ENTRY_SPLIT:.*]] [
; CHECK-NEXT:      i32 1, label %[[LOOP1_PREHEADER_SPLIT_LOOP_EXIT:.*]]
; CHECK-NEXT:    ]
; CHECK:       [[ENTRY_SPLIT]]:
; CHECK-NEXT:    br label %[[LOOP0_PRE:.*]]
; CHECK:       [[LOOP0_PRE]]:
; CHECK-NEXT:    br i1 [[CHECK]], label %[[EXIT:.*]], label %[[LOOP0:.*]]
; CHECK:       [[LOOP0]]:
; CHECK-NEXT:    [[LENGTH:%.*]] = load atomic i32, ptr addrspace(1) [[P]] unordered, align 4
; CHECK-NEXT:    [[TMP0:%.*]] = icmp ugt i32 [[LENGTH]], 1
; CHECK-NEXT:    br i1 [[TMP0]], label %[[LOOP0_OUT:.*]], label %[[LOOP1_PREHEADER_SPLIT_LOOP_EXIT1:.*]]
; CHECK:       [[LOOP0_OUT]]:
; CHECK-NEXT:    br label %[[LOOP0_PRE]]
; CHECK:       [[LOOP1_PREHEADER_SPLIT_LOOP_EXIT]]:
; CHECK-NEXT:    [[T_LE:%.*]] = add i32 0, 1
; CHECK-NEXT:    br label %[[LOOP1_PREHEADER:.*]]
; CHECK:       [[LOOP1_PREHEADER_SPLIT_LOOP_EXIT1]]:
; CHECK-NEXT:    [[LENGTH_LCSSA_PH2:%.*]] = phi i32 [ [[LENGTH]], %[[LOOP0]] ]
; CHECK-NEXT:    [[LOCAL_PH3:%.*]] = phi i32 [ 0, %[[LOOP0]] ]
; CHECK-NEXT:    br label %[[LOOP1_PREHEADER]]
; CHECK:       [[LOOP1_PREHEADER]]:
; CHECK-NEXT:    [[LENGTH_LCSSA:%.*]] = phi i32 [ poison, %[[LOOP1_PREHEADER_SPLIT_LOOP_EXIT]] ], [ [[LENGTH_LCSSA_PH2]], %[[LOOP1_PREHEADER_SPLIT_LOOP_EXIT1]] ]
; CHECK-NEXT:    [[LOCAL:%.*]] = phi i32 [ [[T_LE]], %[[LOOP1_PREHEADER_SPLIT_LOOP_EXIT]] ], [ [[LOCAL_PH3]], %[[LOOP1_PREHEADER_SPLIT_LOOP_EXIT1]] ]
; CHECK-NEXT:    [[TMP1:%.*]] = add i32 [[LENGTH_LCSSA]], -1
; CHECK-NEXT:    [[TMP2:%.*]] = icmp ult i32 310, [[TMP1]]
; CHECK-NEXT:    [[TMP3:%.*]] = icmp ult i32 4, [[LENGTH_LCSSA]]
; CHECK-NEXT:    [[TMP4:%.*]] = and i1 [[TMP3]], [[TMP2]]
; CHECK-NEXT:    [[TMP5:%.*]] = freeze i1 [[TMP4]]
; CHECK-NEXT:    br label %[[LOOP1:.*]]
; CHECK:       [[LOOP1]]:
; CHECK-NEXT:    [[IV1:%.*]] = phi i32 [ 4, %[[LOOP1_PREHEADER]] ], [ [[IV1_NEXT:%.*]], %[[LOOP1_GUARDED:.*]] ]
; CHECK-NEXT:    [[TMP6:%.*]] = icmp ult i32 [[IV1]], [[LENGTH_LCSSA]]
; CHECK-NEXT:    [[WC:%.*]] = call i1 @llvm.experimental.widenable.condition()
; CHECK-NEXT:    [[TMP7:%.*]] = and i1 [[TMP5]], [[WC]]
; CHECK-NEXT:    br i1 [[TMP7]], label %[[LOOP1_GUARDED]], label %[[DEOPT_EXIT:.*]]
; CHECK:       [[LOOP1_GUARDED]]:
; CHECK-NEXT:    call void @llvm.assume(i1 [[TMP6]])
; CHECK-NEXT:    [[IV1_NEXT]] = add nuw nsw i32 [[IV1]], 1
; CHECK-NEXT:    [[CHK:%.*]] = icmp ugt i32 [[IV1]], 310
; CHECK-NEXT:    br i1 [[CHK]], label %[[LOOP1_EXIT:.*]], label %[[LOOP1]]
; CHECK:       [[DEOPT_EXIT]]:
; CHECK-NEXT:    [[TMP8:%.*]] = call i64 (...) @llvm.experimental.deoptimize.i64(i32 13) [ "deopt"() ]
; CHECK-NEXT:    ret i64 [[TMP8]]
; CHECK:       [[LOOP1_EXIT]]:
; CHECK-NEXT:    ret i64 0
; CHECK:       [[EXIT]]:
; CHECK-NEXT:    ret i64 0
;
entry:
  br label %loop0.pre

loop0.pre:
  br i1 %check, label %exit, label %loop0

loop0:
  %length = load atomic i32, ptr addrspace(1) %p unordered, align 4
  %28 = icmp ugt i32 %length, 1
  br i1 %28, label %loop0.out, label %loop1.preheader

loop0.out:
  %t = add i32 0, 1
  br i1 false, label %loop1.preheader, label %mid

loop1.preheader:
  %length.lcssa = phi i32 [ %length, %loop0.out ], [ %length, %loop0 ]
  %local = phi i32 [ 0, %loop0 ], [ %t, %loop0.out ]
  br label %loop1

loop1:
  %iv1 = phi i32 [ 4, %loop1.preheader ], [ %iv1.next, %loop1.guarded ]
  %82 = icmp ult i32 %iv1, %length.lcssa
  %wc = call i1 @llvm.experimental.widenable.condition()
  %guard.chk = and i1 %82, %wc
  br i1 %guard.chk, label %loop1.guarded, label %deopt-exit

loop1.guarded:
  %iv1.next = add nuw nsw i32 %iv1, 1
  %chk = icmp ugt i32 %iv1, 310
  br i1 %chk, label %loop1.exit, label %loop1

deopt-exit:
  %100 = call i64 (...) @llvm.experimental.deoptimize.i64(i32 13) [ "deopt"() ]
  ret i64 %100

loop1.exit:
  ret i64 0

mid:
  br label %loop0.pre

exit:
  ret i64 0
}

declare i64 @foo()

declare i64 @llvm.experimental.deoptimize.i64(...)

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(inaccessiblemem: readwrite)
declare noundef i1 @llvm.experimental.widenable.condition()
