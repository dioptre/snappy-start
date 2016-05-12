# Copyright 2015 Google Inc. All Rights Reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from __future__ import print_function

import struct
import subprocess


__NR_mmap = 9
__NR_getpid = 39
__NR_mknod = 133


def AssertEquals(x, y):
  if x != y:
    raise AssertionError('%r != %r' % (x, y))


def RunTest(cmd, sysnum, use_elf_loader=True):
  if use_elf_loader:
    cmd = ['./out/elf_loader'] + cmd
  print('* Running test: %s' % ' '.join(cmd))
  output = subprocess.Popen(['./out/ptracer'] + cmd, stderr=subprocess.PIPE) \
      .communicate()[1];

  # Check that the program was snapshotted at the expected syscall.
  # Otherwise, it could have been stopped earlier than we expected,
  # which would mean we wouldn't be testing the parts we expected to
  # test.
  AssertEquals("record ended due to syscall: %d\n" % sysnum, output.decode())

  subprocess.check_call(['./replay.out'])


def Main():
  # This is a bare-bones test that does not need to be run through
  # elf_loader in order to be restored.
  RunTest(['./out/example_loader'], -1, use_elf_loader=False)

  RunTest(['./out/example_prog'], __NR_getpid)
  RunTest(['./out/example_prog2'], -1)

  # Get list of sub-test names.
  proc = subprocess.Popen(['./out/save_restore_tests'], stdout=subprocess.PIPE)
  stdout = proc.communicate()[0]
  test_names = stdout.strip().decode().split('\n')

  sysnum_for_test = {
    'test_mknod_not_whitelisted': __NR_mknod,
    'test_mmap_map_shared': __NR_mmap,
  }
  for test_name in test_names:
    RunTest(['./out/save_restore_tests', test_name],
            sysnum_for_test.get(test_name, -1))

  RunTest(['/usr/bin/python', 'tests/python_example.py'], __NR_mknod)


if __name__ == '__main__':
  Main()
