//===-- Unittests for isatty ----------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "src/fcntl/open.h"
#include "src/unistd/close.h"
#include "src/unistd/isatty.h"
#include "test/UnitTest/ErrnoCheckingTest.h"
#include "test/UnitTest/ErrnoSetterMatcher.h"
#include "test/UnitTest/Test.h"

#include <sys/stat.h>

using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Succeeds;
using LlvmLibcIsATTYTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;

TEST_F(LlvmLibcIsATTYTest, StdInOutTests) {
  // If stdin is connected to a terminal, assume that all of the standard i/o
  // fds are.
  if (LIBC_NAMESPACE::isatty(0)) {
    EXPECT_THAT(LIBC_NAMESPACE::isatty(0), Succeeds(1)); // stdin
    EXPECT_THAT(LIBC_NAMESPACE::isatty(1), Succeeds(1)); // stdout
    EXPECT_THAT(LIBC_NAMESPACE::isatty(2), Succeeds(1)); // stderr
  } else {
    EXPECT_THAT(LIBC_NAMESPACE::isatty(0), Fails(ENOTTY, 0)); // stdin
    EXPECT_THAT(LIBC_NAMESPACE::isatty(1), Fails(ENOTTY, 0)); // stdout
    EXPECT_THAT(LIBC_NAMESPACE::isatty(2), Fails(ENOTTY, 0)); // stderr
  }
}

TEST_F(LlvmLibcIsATTYTest, BadFdTest) {
  EXPECT_THAT(LIBC_NAMESPACE::isatty(-1), Fails(EBADF, 0)); // invalid fd
}

TEST_F(LlvmLibcIsATTYTest, DevTTYTest) {
  constexpr const char *FILENAME = "/dev/tty";
  auto TTY_FILE = libc_make_test_file_path(FILENAME);
  int fd = LIBC_NAMESPACE::open(TTY_FILE, O_RDONLY);
  if (fd > 0) {
    ASSERT_ERRNO_SUCCESS();
    EXPECT_THAT(LIBC_NAMESPACE::isatty(fd), Succeeds(1));
    ASSERT_THAT(LIBC_NAMESPACE::close(fd), Succeeds(0));
  } else {
    ASSERT_ERRNO_FAILURE();
  }
}

TEST_F(LlvmLibcIsATTYTest, FileTest) {
  constexpr const char *FILENAME = "isatty.test";
  auto TEST_FILE = libc_make_test_file_path(FILENAME);
  int fd = LIBC_NAMESPACE::open(TEST_FILE, O_WRONLY | O_CREAT, S_IRWXU);
  ASSERT_ERRNO_SUCCESS();
  ASSERT_GT(fd, 0);
  EXPECT_THAT(LIBC_NAMESPACE::isatty(fd), Fails(ENOTTY, 0));
  ASSERT_THAT(LIBC_NAMESPACE::close(fd), Succeeds(0));
}
