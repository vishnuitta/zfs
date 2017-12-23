![img](http://zfsonlinux.org/images/zfs-linux.png)

ZFS on Linux is an advanced file system and volume manager which was originally
developed for Solaris and is now maintained by the OpenZFS community.

[![codecov](https://codecov.io/gh/zfsonlinux/zfs/branch/master/graph/badge.svg)](https://codecov.io/gh/zfsonlinux/zfs)

# Official Resources
  * [Site](http://zfsonlinux.org)
  * [Wiki](https://github.com/zfsonlinux/zfs/wiki)
  * [Mailing lists](https://github.com/zfsonlinux/zfs/wiki/Mailing-Lists)
  * [OpenZFS site](http://open-zfs.org/)

# Installation
Full documentation for installing ZoL on your favorite Linux distribution can
be found at [our site](http://zfsonlinux.org/).

# Contribute & Develop
We have a separate document with [contribution guidelines](./.github/CONTRIBUTING.md).

# Building
In addition to standard dependencies of ZFS on Linux project following
packages need to be installed:

```bash
sudo apt-get install libaio-dev libgtest-dev cmake
```

Google test framework library does not have a binary package so it needs to be compiled manually:
```bash
cd /usr/src/gtest
sudo cmake -DBUILD_SHARED_LIBS=ON CMakeLists.txt
sudo make

# copy or symlink libgtest.a and libgtest_main.a to your /usr/lib folder
sudo cp *.so /usr/lib
```

Special configure option `--enable-debug` should be used in order to create
zfs and zpool commands which don't call into the kernel using ioctls, but
instead call into uZFS process for serving "ioctls" using tcp connection.
Other than that the build steps are the same as for ZoL:
```bash
./autogen.sh
CFLAGS="-g -O0" ./configure --enable-debug --enable-uzfs=yes
make
```

# Contributing
Make sure to run cstyle on your changes before you submit a pull request:

```bash
make cstyle
```

And assure that the tests are passing. For possible tests to run see .travis.yml
file in root directory. Here is an example of running ztest.

```bash
cmd/ztest/ztest -V
```
