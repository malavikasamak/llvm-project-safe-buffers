; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --version 5
; RUN: opt < %s -passes=instcombine -S | FileCheck %s

; For the following patterns:
; umax(nuw_shl(z, x), nuw_shl(z, y)) -> nuw_shl(z, umax(x, y))
; umin(nuw_shl(z, x), nuw_shl(z, y)) -> nuw_shl(z, umin(x, y))
; umax(nuw_shl(x, z), nuw_shl(y, z)) -> nuw_shl(umax(x, y), z)
; umin(nuw_shl(x, z), nuw_shl(y, z)) -> nuw_shl(umin(x, y), z)

define i32 @umax_shl_common_lhs(i32 %x, i32 %y, i32 %z) {
; CHECK-LABEL: define i32 @umax_shl_common_lhs(
; CHECK-SAME: i32 [[X:%.*]], i32 [[Y:%.*]], i32 [[Z:%.*]]) {
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.umax.i32(i32 [[X]], i32 [[Y]])
; CHECK-NEXT:    [[MAX:%.*]] = shl nuw i32 [[Z]], [[TMP1]]
; CHECK-NEXT:    ret i32 [[MAX]]
;
  %shl_x = shl nuw i32 %z, %x
  %shl_y = shl nuw i32 %z, %y
  %max = call i32 @llvm.umax.i32(i32 %shl_x, i32 %shl_y)
  ret i32 %max
}

define i32 @umax_shl_common_rhs(i32 %x, i32 %y, i32 %z) {
; CHECK-LABEL: define i32 @umax_shl_common_rhs(
; CHECK-SAME: i32 [[X:%.*]], i32 [[Y:%.*]], i32 [[Z:%.*]]) {
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.umax.i32(i32 [[X]], i32 [[Y]])
; CHECK-NEXT:    [[MAX:%.*]] = shl nuw i32 [[TMP1]], [[Z]]
; CHECK-NEXT:    ret i32 [[MAX]]
;
  %shl_x = shl nuw i32 %x, %z
  %shl_y = shl nuw i32 %y, %z
  %max = call i32 @llvm.umax.i32(i32 %shl_x, i32 %shl_y)
  ret i32 %max
}

define i32 @umin_shl_common_lhs(i32 %x, i32 %y, i32 %z) {
; CHECK-LABEL: define i32 @umin_shl_common_lhs(
; CHECK-SAME: i32 [[X:%.*]], i32 [[Y:%.*]], i32 [[Z:%.*]]) {
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.umin.i32(i32 [[X]], i32 [[Y]])
; CHECK-NEXT:    [[MIN:%.*]] = shl nuw i32 [[Z]], [[TMP1]]
; CHECK-NEXT:    ret i32 [[MIN]]
;
  %shl_x = shl nuw i32 %z, %x
  %shl_y = shl nuw i32 %z, %y
  %min = call i32 @llvm.umin.i32(i32 %shl_x, i32 %shl_y)
  ret i32 %min
}

define i32 @umin_shl_common_rhs(i32 %x, i32 %y, i32 %z) {
; CHECK-LABEL: define i32 @umin_shl_common_rhs(
; CHECK-SAME: i32 [[X:%.*]], i32 [[Y:%.*]], i32 [[Z:%.*]]) {
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.umin.i32(i32 [[X]], i32 [[Y]])
; CHECK-NEXT:    [[MIN:%.*]] = shl nuw i32 [[TMP1]], [[Z]]
; CHECK-NEXT:    ret i32 [[MIN]]
;
  %shl_x = shl nuw i32 %x, %z
  %shl_y = shl nuw i32 %y, %z
  %min = call i32 @llvm.umin.i32(i32 %shl_x, i32 %shl_y)
  ret i32 %min
}

define i32 @umax_shl_common_lhs_const1(i32 %x, i32 %y) {
; CHECK-LABEL: define i32 @umax_shl_common_lhs_const1(
; CHECK-SAME: i32 [[X:%.*]], i32 [[Y:%.*]]) {
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.umax.i32(i32 [[X]], i32 [[Y]])
; CHECK-NEXT:    [[MAX:%.*]] = shl nuw i32 1, [[TMP1]]
; CHECK-NEXT:    ret i32 [[MAX]]
;
  %shl_x = shl nuw i32 1, %x
  %shl_y = shl nuw i32 1, %y
  %max = call i32 @llvm.umax.i32(i32 %shl_x, i32 %shl_y)
  ret i32 %max
}

define i32 @umax_shl_common_rhs_const1(i32 %x, i32 %y) {
; CHECK-LABEL: define i32 @umax_shl_common_rhs_const1(
; CHECK-SAME: i32 [[X:%.*]], i32 [[Y:%.*]]) {
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.umax.i32(i32 [[X]], i32 [[Y]])
; CHECK-NEXT:    [[MAX:%.*]] = shl nuw i32 [[TMP1]], 1
; CHECK-NEXT:    ret i32 [[MAX]]
;
  %shl_x = shl nuw i32 %x, 1
  %shl_y = shl nuw i32 %y, 1
  %max = call i32 @llvm.umax.i32(i32 %shl_x, i32 %shl_y)
  ret i32 %max
}

define i32 @umin_shl_common_lhs_const1(i32 %x, i32 %y) {
; CHECK-LABEL: define i32 @umin_shl_common_lhs_const1(
; CHECK-SAME: i32 [[X:%.*]], i32 [[Y:%.*]]) {
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.umin.i32(i32 [[X]], i32 [[Y]])
; CHECK-NEXT:    [[MIN:%.*]] = shl nuw i32 1, [[TMP1]]
; CHECK-NEXT:    ret i32 [[MIN]]
;
  %shl_x = shl nuw i32 1, %x
  %shl_y = shl nuw i32 1, %y
  %min = call i32 @llvm.umin.i32(i32 %shl_x, i32 %shl_y)
  ret i32 %min
}

define i32 @umin_shl_common_rhs_const1(i32 %x, i32 %y) {
; CHECK-LABEL: define i32 @umin_shl_common_rhs_const1(
; CHECK-SAME: i32 [[X:%.*]], i32 [[Y:%.*]]) {
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.umin.i32(i32 [[X]], i32 [[Y]])
; CHECK-NEXT:    [[MIN:%.*]] = shl nuw i32 [[TMP1]], 1
; CHECK-NEXT:    ret i32 [[MIN]]
;
  %shl_x = shl nuw i32 %x, 1
  %shl_y = shl nuw i32 %y, 1
  %min = call i32 @llvm.umin.i32(i32 %shl_x, i32 %shl_y)
  ret i32 %min
}

declare void @use(i8)

define i32 @umax_shl_common_lhs_multi_use(i32 %x, i32 %y, i32 %z) {
; CHECK-LABEL: define i32 @umax_shl_common_lhs_multi_use(
; CHECK-SAME: i32 [[X:%.*]], i32 [[Y:%.*]], i32 [[Z:%.*]]) {
; CHECK-NEXT:    [[SHL_X:%.*]] = shl nuw i32 [[Z]], [[X]]
; CHECK-NEXT:    [[SHL_Y:%.*]] = shl nuw i32 [[Z]], [[Y]]
; CHECK-NEXT:    call void @use(i32 [[SHL_X]])
; CHECK-NEXT:    call void @use(i32 [[SHL_Y]])
; CHECK-NEXT:    [[MAX:%.*]] = call i32 @llvm.umax.i32(i32 [[SHL_X]], i32 [[SHL_Y]])
; CHECK-NEXT:    ret i32 [[MAX]]
;
  %shl_x = shl nuw i32 %z, %x
  %shl_y = shl nuw i32 %z, %y
  call void @use(i32 %shl_x)
  call void @use(i32 %shl_y)
  %max = call i32 @llvm.umax.i32(i32 %shl_x, i32 %shl_y)
  ret i32 %max
}

define i32 @umax_shl_common_rhs_multi_use(i32 %x, i32 %y, i32 %z) {
; CHECK-LABEL: define i32 @umax_shl_common_rhs_multi_use(
; CHECK-SAME: i32 [[X:%.*]], i32 [[Y:%.*]], i32 [[Z:%.*]]) {
; CHECK-NEXT:    [[SHL_X:%.*]] = shl nuw i32 [[X]], [[Z]]
; CHECK-NEXT:    [[SHL_Y:%.*]] = shl nuw i32 [[Y]], [[Z]]
; CHECK-NEXT:    call void @use(i32 [[SHL_X]])
; CHECK-NEXT:    call void @use(i32 [[SHL_Y]])
; CHECK-NEXT:    [[MAX:%.*]] = call i32 @llvm.umax.i32(i32 [[SHL_X]], i32 [[SHL_Y]])
; CHECK-NEXT:    ret i32 [[MAX]]
;
  %shl_x = shl nuw i32 %x, %z
  %shl_y = shl nuw i32 %y, %z
  call void @use(i32 %shl_x)
  call void @use(i32 %shl_y)
  %max = call i32 @llvm.umax.i32(i32 %shl_x, i32 %shl_y)
  ret i32 %max
}

define i32 @umin_shl_common_lhs_multi_use(i32 %x, i32 %y, i32 %z) {
; CHECK-LABEL: define i32 @umin_shl_common_lhs_multi_use(
; CHECK-SAME: i32 [[X:%.*]], i32 [[Y:%.*]], i32 [[Z:%.*]]) {
; CHECK-NEXT:    [[SHL_X:%.*]] = shl nuw i32 [[Z]], [[X]]
; CHECK-NEXT:    [[SHL_Y:%.*]] = shl nuw i32 [[Z]], [[Y]]
; CHECK-NEXT:    call void @use(i32 [[SHL_X]])
; CHECK-NEXT:    call void @use(i32 [[SHL_Y]])
; CHECK-NEXT:    [[MIN:%.*]] = call i32 @llvm.umin.i32(i32 [[SHL_X]], i32 [[SHL_Y]])
; CHECK-NEXT:    ret i32 [[MIN]]
;
  %shl_x = shl nuw i32 %z, %x
  %shl_y = shl nuw i32 %z, %y
  call void @use(i32 %shl_x)
  call void @use(i32 %shl_y)
  %min = call i32 @llvm.umin.i32(i32 %shl_x, i32 %shl_y)
  ret i32 %min
}

define i32 @umin_shl_common_rhs_multi_use(i32 %x, i32 %y, i32 %z) {
; CHECK-LABEL: define i32 @umin_shl_common_rhs_multi_use(
; CHECK-SAME: i32 [[X:%.*]], i32 [[Y:%.*]], i32 [[Z:%.*]]) {
; CHECK-NEXT:    [[SHL_X:%.*]] = shl nuw i32 [[X]], [[Z]]
; CHECK-NEXT:    [[SHL_Y:%.*]] = shl nuw i32 [[Y]], [[Z]]
; CHECK-NEXT:    call void @use(i32 [[SHL_X]])
; CHECK-NEXT:    call void @use(i32 [[SHL_Y]])
; CHECK-NEXT:    [[MIN:%.*]] = call i32 @llvm.umin.i32(i32 [[SHL_X]], i32 [[SHL_Y]])
; CHECK-NEXT:    ret i32 [[MIN]]
;
  %shl_x = shl nuw i32 %x, %z
  %shl_y = shl nuw i32 %y, %z
  call void @use(i32 %shl_x)
  call void @use(i32 %shl_y)
  %min = call i32 @llvm.umin.i32(i32 %shl_x, i32 %shl_y)
  ret i32 %min
}

define i32 @umax_shl_common_lhs_commuted(i32 %x, i32 %y, i32 %z) {
; CHECK-LABEL: define i32 @umax_shl_common_lhs_commuted(
; CHECK-SAME: i32 [[X:%.*]], i32 [[Y:%.*]], i32 [[Z:%.*]]) {
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.umax.i32(i32 [[Y]], i32 [[X]])
; CHECK-NEXT:    [[MAX:%.*]] = shl nuw i32 [[Z]], [[TMP1]]
; CHECK-NEXT:    ret i32 [[MAX]]
;
  %shl_x = shl nuw i32 %z, %x
  %shl_y = shl nuw i32 %z, %y
  %max = call i32 @llvm.umax.i32(i32 %shl_y, i32 %shl_x)
  ret i32 %max
}

define i32 @umax_shl_common_rhs_commuted(i32 %x, i32 %y, i32 %z) {
; CHECK-LABEL: define i32 @umax_shl_common_rhs_commuted(
; CHECK-SAME: i32 [[X:%.*]], i32 [[Y:%.*]], i32 [[Z:%.*]]) {
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.umax.i32(i32 [[Y]], i32 [[X]])
; CHECK-NEXT:    [[MAX:%.*]] = shl nuw i32 [[TMP1]], [[Z]]
; CHECK-NEXT:    ret i32 [[MAX]]
;
  %shl_x = shl nuw i32 %x, %z
  %shl_y = shl nuw i32 %y, %z
  %max = call i32 @llvm.umax.i32(i32 %shl_y, i32 %shl_x)
  ret i32 %max
}

define i32 @umin_shl_common_lhs_commuted(i32 %x, i32 %y, i32 %z) {
; CHECK-LABEL: define i32 @umin_shl_common_lhs_commuted(
; CHECK-SAME: i32 [[X:%.*]], i32 [[Y:%.*]], i32 [[Z:%.*]]) {
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.umin.i32(i32 [[Y]], i32 [[X]])
; CHECK-NEXT:    [[MIN:%.*]] = shl nuw i32 [[Z]], [[TMP1]]
; CHECK-NEXT:    ret i32 [[MIN]]
;
  %shl_x = shl nuw i32 %z, %x
  %shl_y = shl nuw i32 %z, %y
  %min = call i32 @llvm.umin.i32(i32 %shl_y, i32 %shl_x)
  ret i32 %min
}

define i32 @umin_shl_common_rhs_commuted(i32 %x, i32 %y, i32 %z) {
; CHECK-LABEL: define i32 @umin_shl_common_rhs_commuted(
; CHECK-SAME: i32 [[X:%.*]], i32 [[Y:%.*]], i32 [[Z:%.*]]) {
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.umin.i32(i32 [[Y]], i32 [[X]])
; CHECK-NEXT:    [[MIN:%.*]] = shl nuw i32 [[TMP1]], [[Z]]
; CHECK-NEXT:    ret i32 [[MIN]]
;
  %shl_x = shl nuw i32 %x, %z
  %shl_y = shl nuw i32 %y, %z
  %min = call i32 @llvm.umin.i32(i32 %shl_y, i32 %shl_x)
  ret i32 %min
}

define <2 x i32> @umax_shl_common_lhs_vector(<2 x i32> %z, <2 x i32> %x, <2 x i32> %y) {
; CHECK-LABEL: define <2 x i32> @umax_shl_common_lhs_vector(
; CHECK-SAME: <2 x i32> [[Z:%.*]], <2 x i32> [[X:%.*]], <2 x i32> [[Y:%.*]]) {
; CHECK-NEXT:    [[TMP1:%.*]] = call <2 x i32> @llvm.umax.v2i32(<2 x i32> [[X]], <2 x i32> [[Y]])
; CHECK-NEXT:    [[MAX:%.*]] = shl nuw <2 x i32> [[Z]], [[TMP1]]
; CHECK-NEXT:    ret <2 x i32> [[MAX]]
;
  %shl_x = shl nuw <2 x i32> %z, %x
  %shl_y = shl nuw <2 x i32> %z, %y
  %max = call <2 x i32> @llvm.umax.v2i32(<2 x i32> %shl_x, <2 x i32> %shl_y)
  ret <2 x i32> %max
}

define <2 x i32> @umax_shl_common_rhs_vector(<2 x i32> %z, <2 x i32> %x, <2 x i32> %y) {
; CHECK-LABEL: define <2 x i32> @umax_shl_common_rhs_vector(
; CHECK-SAME: <2 x i32> [[Z:%.*]], <2 x i32> [[X:%.*]], <2 x i32> [[Y:%.*]]) {
; CHECK-NEXT:    [[TMP1:%.*]] = call <2 x i32> @llvm.umax.v2i32(<2 x i32> [[X]], <2 x i32> [[Y]])
; CHECK-NEXT:    [[MAX:%.*]] = shl nuw <2 x i32> [[TMP1]], [[Z]]
; CHECK-NEXT:    ret <2 x i32> [[MAX]]
;
  %shl_x = shl nuw <2 x i32> %x, %z
  %shl_y = shl nuw <2 x i32> %y, %z
  %max = call <2 x i32> @llvm.umax.v2i32(<2 x i32> %shl_x, <2 x i32> %shl_y)
  ret <2 x i32> %max
}


define <2 x i32> @umin_shl_common_lhs_vector(<2 x i32> %z, <2 x i32> %x, <2 x i32> %y) {
; CHECK-LABEL: define <2 x i32> @umin_shl_common_lhs_vector(
; CHECK-SAME: <2 x i32> [[Z:%.*]], <2 x i32> [[X:%.*]], <2 x i32> [[Y:%.*]]) {
; CHECK-NEXT:    [[TMP1:%.*]] = call <2 x i32> @llvm.umin.v2i32(<2 x i32> [[X]], <2 x i32> [[Y]])
; CHECK-NEXT:    [[MIN:%.*]] = shl nuw <2 x i32> [[Z]], [[TMP1]]
; CHECK-NEXT:    ret <2 x i32> [[MIN]]
;
  %shl_x = shl nuw <2 x i32> %z, %x
  %shl_y = shl nuw <2 x i32> %z, %y
  %min = call <2 x i32> @llvm.umin.v2i32(<2 x i32> %shl_x, <2 x i32> %shl_y)
  ret <2 x i32> %min
}

define <2 x i32> @umin_shl_common_rhs_vector(<2 x i32> %z, <2 x i32> %x, <2 x i32> %y) {
; CHECK-LABEL: define <2 x i32> @umin_shl_common_rhs_vector(
; CHECK-SAME: <2 x i32> [[Z:%.*]], <2 x i32> [[X:%.*]], <2 x i32> [[Y:%.*]]) {
; CHECK-NEXT:    [[TMP1:%.*]] = call <2 x i32> @llvm.umin.v2i32(<2 x i32> [[X]], <2 x i32> [[Y]])
; CHECK-NEXT:    [[MIN:%.*]] = shl nuw <2 x i32> [[TMP1]], [[Z]]
; CHECK-NEXT:    ret <2 x i32> [[MIN]]
;
  %shl_x = shl nuw <2 x i32> %x, %z
  %shl_y = shl nuw <2 x i32> %y, %z
  %min = call <2 x i32> @llvm.umin.v2i32(<2 x i32> %shl_x, <2 x i32> %shl_y)
  ret <2 x i32> %min
}

; Negative tests

define i32 @umax_shl_different_lhs(i32 %z1, i32 %z2, i32 %x, i32 %y) {
; CHECK-LABEL: define i32 @umax_shl_different_lhs(
; CHECK-SAME: i32 [[Z1:%.*]], i32 [[Z2:%.*]], i32 [[X:%.*]], i32 [[Y:%.*]]) {
; CHECK-NEXT:    [[SHL_X:%.*]] = shl nuw i32 [[Z1]], [[X]]
; CHECK-NEXT:    [[SHL_Y:%.*]] = shl nuw i32 [[Z2]], [[Y]]
; CHECK-NEXT:    [[MAX:%.*]] = call i32 @llvm.umax.i32(i32 [[SHL_X]], i32 [[SHL_Y]])
; CHECK-NEXT:    ret i32 [[MAX]]
;
  %shl_x = shl nuw i32 %z1, %x
  %shl_y = shl nuw i32 %z2, %y
  %max = call i32 @llvm.umax.i32(i32 %shl_x, i32 %shl_y)
  ret i32 %max
}

define i32 @umax_shl_different_rhs(i32 %z1, i32 %z2, i32 %x, i32 %y) {
; CHECK-LABEL: define i32 @umax_shl_different_rhs(
; CHECK-SAME: i32 [[Z1:%.*]], i32 [[Z2:%.*]], i32 [[X:%.*]], i32 [[Y:%.*]]) {
; CHECK-NEXT:    [[SHL_X:%.*]] = shl nuw i32 [[X]], [[Z1]]
; CHECK-NEXT:    [[SHL_Y:%.*]] = shl nuw i32 [[Y]], [[Z2]]
; CHECK-NEXT:    [[MAX:%.*]] = call i32 @llvm.umax.i32(i32 [[SHL_X]], i32 [[SHL_Y]])
; CHECK-NEXT:    ret i32 [[MAX]]
;
  %shl_x = shl nuw i32 %x, %z1
  %shl_y = shl nuw i32 %y, %z2
  %max = call i32 @llvm.umax.i32(i32 %shl_x, i32 %shl_y)
  ret i32 %max
}

define i32 @umin_shl_different_lhs(i32 %z1, i32 %z2, i32 %x, i32 %y) {
; CHECK-LABEL: define i32 @umin_shl_different_lhs(
; CHECK-SAME: i32 [[Z1:%.*]], i32 [[Z2:%.*]], i32 [[X:%.*]], i32 [[Y:%.*]]) {
; CHECK-NEXT:    [[SHL_X:%.*]] = shl nuw i32 [[Z1]], [[X]]
; CHECK-NEXT:    [[SHL_Y:%.*]] = shl nuw i32 [[Z2]], [[Y]]
; CHECK-NEXT:    [[MIN:%.*]] = call i32 @llvm.umin.i32(i32 [[SHL_X]], i32 [[SHL_Y]])
; CHECK-NEXT:    ret i32 [[MIN]]
;
  %shl_x = shl nuw i32 %z1, %x
  %shl_y = shl nuw i32 %z2, %y
  %min = call i32 @llvm.umin.i32(i32 %shl_x, i32 %shl_y)
  ret i32 %min
}

define i32 @umin_shl_different_rhs(i32 %z1, i32 %z2, i32 %x, i32 %y) {
; CHECK-LABEL: define i32 @umin_shl_different_rhs(
; CHECK-SAME: i32 [[Z1:%.*]], i32 [[Z2:%.*]], i32 [[X:%.*]], i32 [[Y:%.*]]) {
; CHECK-NEXT:    [[SHL_X:%.*]] = shl nuw i32 [[X]], [[Z1]]
; CHECK-NEXT:    [[SHL_Y:%.*]] = shl nuw i32 [[Y]], [[Z2]]
; CHECK-NEXT:    [[MIN:%.*]] = call i32 @llvm.umin.i32(i32 [[SHL_X]], i32 [[SHL_Y]])
; CHECK-NEXT:    ret i32 [[MIN]]
;
  %shl_x = shl nuw i32 %x, %z1
  %shl_y = shl nuw i32 %y, %z2
  %min = call i32 @llvm.umin.i32(i32 %shl_x, i32 %shl_y)
  ret i32 %min
}

define i32 @umax_shl_does_not_commute(i32 %x, i32 %y, i32 %z) {
; CHECK-LABEL: define i32 @umax_shl_does_not_commute(
; CHECK-SAME: i32 [[X:%.*]], i32 [[Y:%.*]], i32 [[Z:%.*]]) {
; CHECK-NEXT:    [[SHL_X:%.*]] = shl nuw i32 [[X]], [[Y]]
; CHECK-NEXT:    [[SHL_Y:%.*]] = shl nuw i32 [[Y]], [[Z]]
; CHECK-NEXT:    [[MAX:%.*]] = call i32 @llvm.umax.i32(i32 [[SHL_X]], i32 [[SHL_Y]])
; CHECK-NEXT:    ret i32 [[MAX]]
;
  %shl_x = shl nuw i32 %x, %y
  %shl_y = shl nuw i32 %y, %z
  %max = call i32 @llvm.umax.i32(i32 %shl_x, i32 %shl_y)
  ret i32 %max
}

define i32 @umin_shl_does_not_commute(i32 %x, i32 %y, i32 %z) {
; CHECK-LABEL: define i32 @umin_shl_does_not_commute(
; CHECK-SAME: i32 [[X:%.*]], i32 [[Y:%.*]], i32 [[Z:%.*]]) {
; CHECK-NEXT:    [[SHL_X:%.*]] = shl nuw i32 [[X]], [[Y]]
; CHECK-NEXT:    [[SHL_Y:%.*]] = shl nuw i32 [[Y]], [[Z]]
; CHECK-NEXT:    [[MIN:%.*]] = call i32 @llvm.umin.i32(i32 [[SHL_X]], i32 [[SHL_Y]])
; CHECK-NEXT:    ret i32 [[MIN]]
;
  %shl_x = shl nuw i32 %x, %y
  %shl_y = shl nuw i32 %y, %z
  %min = call i32 @llvm.umin.i32(i32 %shl_x, i32 %shl_y)
  ret i32 %min
}

define i32 @umax_shl_common_lhs_no_nuw_flag(i32 %x, i32 %y) {
; CHECK-LABEL: define i32 @umax_shl_common_lhs_no_nuw_flag(
; CHECK-SAME: i32 [[X:%.*]], i32 [[Y:%.*]]) {
; CHECK-NEXT:    [[SHL_X:%.*]] = shl i32 2, [[X]]
; CHECK-NEXT:    [[SHL_Y:%.*]] = shl i32 2, [[Y]]
; CHECK-NEXT:    [[MAX:%.*]] = call i32 @llvm.umax.i32(i32 [[SHL_X]], i32 [[SHL_Y]])
; CHECK-NEXT:    ret i32 [[MAX]]
;
  %shl_x = shl i32 2, %x
  %shl_y = shl i32 2, %y
  %max = call i32 @llvm.umax.i32(i32 %shl_x, i32 %shl_y)
  ret i32 %max
}

define i32 @umax_shl_common_rhs_no_nuw_flag(i32 %x, i32 %y) {
; CHECK-LABEL: define i32 @umax_shl_common_rhs_no_nuw_flag(
; CHECK-SAME: i32 [[X:%.*]], i32 [[Y:%.*]]) {
; CHECK-NEXT:    [[SHL_X:%.*]] = shl nuw i32 [[X]], 2
; CHECK-NEXT:    [[SHL_Y:%.*]] = shl i32 [[Y]], 2
; CHECK-NEXT:    [[MAX:%.*]] = call i32 @llvm.umax.i32(i32 [[SHL_X]], i32 [[SHL_Y]])
; CHECK-NEXT:    ret i32 [[MAX]]
;
  %shl_x = shl nuw i32 %x, 2
  %shl_y = shl i32 %y, 2
  %max = call i32 @llvm.umax.i32(i32 %shl_x, i32 %shl_y)
  ret i32 %max
}

define i32 @umax_shl_common_lhs_preserve_nsw(i32 %x, i32 %y, i32 %z) {
; CHECK-LABEL: define i32 @umax_shl_common_lhs_preserve_nsw(
; CHECK-SAME: i32 [[X:%.*]], i32 [[Y:%.*]], i32 [[Z:%.*]]) {
; CHECK-NEXT:    [[TMP1:%.*]] = call i32 @llvm.umax.i32(i32 [[X]], i32 [[Y]])
; CHECK-NEXT:    [[MAX:%.*]] = shl nuw nsw i32 [[Z]], [[TMP1]]
; CHECK-NEXT:    ret i32 [[MAX]]
;
  %shl_x = shl nuw nsw i32 %z, %x
  %shl_y = shl nuw nsw i32 %z, %y
  %max = call i32 @llvm.umax.i32(i32 %shl_x, i32 %shl_y)
  ret i32 %max
}
