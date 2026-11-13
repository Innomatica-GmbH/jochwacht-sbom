# Yocto excerpt: yocto-baum-scarthgap-4

Real files, byte for byte, from infra's build jochwacht-yocto-spdx #4
(poky scarthgap b6ae714a1d1bfae8384654a13da15996cac64712, qemux86-64,
core-image-minimal, PACKAGE_CLASSES "package_rpm package_ipk", 13.11.2026).
Archive: jochwacht-eval/yocto-baum-scarthgap-4.tar.zst, sha256 verified.

Two exceptions, both excerpts and not inventions:

- `deploy/images/qemux86-64/*.testdata.json` holds 15 of the image's testdata
  keys, values unchanged (the full file is the whole datastore, 209 KB). The
  undated name is a symlink to the dated file, as in the build. The image
  manifest is complete and unchanged (dated file plus symlink).
- `deploy/images/qemux86-64/<IMAGE_NAME>.tar.bz2` is a smaller tar of the same
  name holding 9 members of the real rootfs tar (18 MB): `bin`, `etc`, `lib`,
  `bin/start_getty`, `etc/hostname`, `etc/ld.so.cache`, `etc/mtab` (symlink),
  `etc/protocols`, `lib/libdl.so.2`, `lib/libnss_files.so.2`. Member headers
  (mode, owner, mtime) and bytes are copied unchanged; the tar container
  itself is new, so its own hash differs from the build's.

sha256 of every file:

```
93e77baa1a5dc8b9cc98d789b3639ad08ccaf9ddb753f1bd84d53d8459f24581  tmp/deploy/images/qemux86-64/core-image-minimal-qemux86-64.rootfs-20261113162618.manifest
f74636cf2fc23bb39337fbf2d91f402b3cf07bb6cb203612775025e6bab094bc  tmp/deploy/images/qemux86-64/core-image-minimal-qemux86-64.rootfs-20261113162618.tar.bz2
82a5577b5cde80c69d5f10c8e16346508b4651a10c0c97be55f9cf7b81b29ad0  tmp/deploy/images/qemux86-64/core-image-minimal-qemux86-64.rootfs-20261113162618.testdata.json
f693b638da97469f09095b702b56db8e5f6158d00007f758216511201c1f22cc  tmp/deploy/rpm/core2_64/libattr1-2.5.1-r0.core2_64.rpm
f2e47e53f22f3a708872b54670e4027df2fdeb50dc5c9b8bf80a02df7ef94945  tmp/deploy/rpm/core2_64/libedit0-20230828+3.1-r1.core2_64.rpm
2a0894c9ba6fd3e0ee86cfded591224e963a54af568e24389e92affe8c294c86  tmp/deploy/rpm/noarch/netbase-6.4-r0.noarch.rpm
4dd442a3f69e099076bb4b6b1c53108fda7ca12f84d4778ac652f3df349fcbe9  tmp/deploy/rpm/qemux86_64/base-files-3.0.14-r0.qemux86_64.rpm
acc80bac4bc2c23ebd7e1fda62a2293f4d7fde74ae8e665d2fa4e2272cb9abd6  tmp/deploy/spdx/2.2/allarch/packages/netbase.spdx.json
9cacd040722a867dc34968409cacdf6112fcca80628c29b7992c0801ed5ac71f  tmp/deploy/spdx/2.2/allarch/recipes/recipe-netbase.spdx.json
4517bd2e8f15421031e202181836c564d6602b0d2e04f5381f04e24fc83ceb00  tmp/deploy/spdx/2.2/core2-64/packages/libattr1.spdx.json
db5a2495b4c970e58d4765d5daf0c7fb178d645458fc1ef429247244128396eb  tmp/deploy/spdx/2.2/core2-64/packages/libedit0.spdx.json
58744f8272e432e303ab2bc37dad4899f073bd97f038e96cb82cac3e8081565e  tmp/deploy/spdx/2.2/core2-64/recipes/recipe-attr.spdx.json
d5910b2e3d4ca189d5e8093e8aecfb1fbabf4f06c1b59d665f40d5e6ecbabd22  tmp/deploy/spdx/2.2/core2-64/recipes/recipe-glibc.spdx.json
fc12d2a7ad1adc9bb75b9287de0ceabe39e9f0736216158b1d466a84a0667b8b  tmp/deploy/spdx/2.2/qemux86_64/packages/base-files.spdx.json
0058b05bfbeb6f7d82b0fe4dfd49e838902d97248eb8e40abc004d37207a8887  tmp/deploy/spdx/2.2/qemux86_64/packages/sysvinit-inittab.spdx.json
c4ffe9c1f9a9fd5c9fa489a19208496c4378bfa1eb0af7f1b153601fbf9df5a1  tmp/deploy/spdx/2.2/qemux86_64/recipes/recipe-base-files.spdx.json
faeb588553258152997909c496dea77e053c35a36da46e9c7e73e76e6515ec60  tmp/deploy/spdx/2.2/qemux86_64/recipes/recipe-linux-yocto.spdx.json
868fb0cc5530b88d251da433c14b8c50f6076ebea17a58199e36540c4024b6e7  tmp/deploy/spdx/2.2/qemux86_64/recipes/recipe-sysvinit-inittab.spdx.json
c4d141e3737e072a5a5154b4f924d81f058b51c9389a2f52f109b9139fd3973a  tmp/pkgdata/qemux86-64/runtime/attr-staticdev
acda24db739f8fb3c291ea4b67d4348dc8ece902ea9a009e9d26d04f110ef086  tmp/pkgdata/qemux86-64/runtime/base-files
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  tmp/pkgdata/qemux86-64/runtime/base-files.packaged
aeeb6fc642756ecb3b27d14556fb8939870a9e8576051dcfd0cb9729478f6d21  tmp/pkgdata/qemux86-64/runtime/glibc
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  tmp/pkgdata/qemux86-64/runtime/glibc.packaged
ce2da93b88cc779a65d8b010ebcb8d490667e9493768040034a53626645b3379  tmp/pkgdata/qemux86-64/runtime/libattr
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  tmp/pkgdata/qemux86-64/runtime/libattr.packaged
eb25e0f97dda774e5c6ec7962a8f0590fcc6f8056b55e7e321a860ddd4e3ac97  tmp/pkgdata/qemux86-64/runtime/libedit
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  tmp/pkgdata/qemux86-64/runtime/libedit.packaged
4a57badac2de619ffe5fe90937a0708884e0229bb39944fec88943234ae7d97b  tmp/pkgdata/qemux86-64/runtime/netbase
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  tmp/pkgdata/qemux86-64/runtime/netbase.packaged
22f804c1bf18c4bef98d35f56e826a90e910b5732a56a1a9c62ed908a3b1d4e2  tmp/pkgdata/qemux86-64/runtime/sysvinit-inittab
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  tmp/pkgdata/qemux86-64/runtime/sysvinit-inittab.packaged
```
