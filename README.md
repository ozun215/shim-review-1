This repo is for review of requests for signing shim.  To create a request for review:

- clone this repo
- edit the template below
- add the shim.efi to be signed
- add build logs
- add any additional binaries/certificates/SHA256 hashes that may be needed
- commit all of that
- tag it with a tag of the form "myorg-shim-arch-YYYYMMDD"
- push that to github
- file an issue at https://github.com/rhboot/shim-review/issues with a link to your tag
- approval is ready when the "accepted" label is added to your issue

Note that we really only have experience with using GRUB2 or systemd-boot on Linux, so
asking us to endorse anything else for signing is going to require some convincing on
your part.

Check the docs directory in this repo for guidance on submission and
getting your shim signed.

Here's the template:

*******************************************************************************
### What organization or people are asking to have this signed?
*******************************************************************************
Gooroom Platform Forum (www.gooroom.kr).

Gooroom platforms are being developed in consideration of cloud-web-based work environments that perform all tasks on a secure browser. Cloud-web-based work environments store all data in cloud storage and work by utilizing the web-based application services provided by the cloud instead of the applications that were previously installed and running on user terminals.

Gooroom platform consists of Gooroom OS, Gooroom browser, Gooroom security technology, and Gooroom central management System

Korean companies such as HANCOM Inc.(www.hancom.com), AhnLab Inc.(www.ahnlab.com), and TmaxOS(www.tmax.co.kr), eActive(www.eactive.co.kr) are participating in the Gooroom Platform Forum.

*******************************************************************************
### What product or service is this for?
*******************************************************************************
Gooroom OS.
Gooroom OS is a Debian-based Linux distribution, and like other open source OSes, anyone can use the source code and binaries for free.
Gooroom OS is a secure OS that provides sufficient support for multilevel security. It was created to prepare for the transition to the cloud.

*******************************************************************************
### What's the justification that this really does need to be signed for the whole world to be able to boot it?
*******************************************************************************
Gooroom OS is an open source OS that anyone can use freely, such as Debian, Ubuntu, and Fedora.
Gooroom OS has been developed and released up to version 3.0.
Gooroom OS currently supports Secure Boot but, there is no SHIM signed by MS, Secure Boot is only available on PC that could register custom keys in UEFI.
If we get a shim signed by Microsoft, users around the world will be able to use Gooroom OS more easily and safely.

*******************************************************************************
### Why are you unable to reuse shim from another distro that is already signed?
*******************************************************************************

This is our first submission. and our OS is custom build for secure reason.

*******************************************************************************
### Who is the primary contact for security updates, etc.?
The security contacts need to be verified before the shim can be accepted. For subsequent requests, contact verification is only necessary if the security contacts or their PGP keys have changed since the last successful verification.

An authorized reviewer will initiate contact verification by sending each security contact a PGP-encrypted email containing random words.
You will be asked to post the contents of these mails in your `shim-review` issue to prove ownership of the email addresses and PGP keys.
*******************************************************************************
- Name: JongKyung Woo
- Position: Gooroom Director
- Email address: jongkyung.woo@gmail.com
- PGP key fingerprint: E26BB70BCCAD03A97642D44D52AD80DDD37121DB
  
(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

*******************************************************************************
### Who is the secondary contact for security updates, etc.?
*******************************************************************************
- Name: YoungJun Park
- Position: Gooroom OS Engineer
- Email address: zunn@eactive.co.kr
- PGP key fingerprint: 4D3B299E25CBC5C57FCB2801C52AD23FD5E6CAE9

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

*******************************************************************************
### Were these binaries created from the 15.8 shim release tar?
Please create your shim binaries starting with the 15.8 shim release tar file: https://github.com/rhboot/shim/releases/download/15.8/shim-15.8.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/15.8 and contains the appropriate gnu-efi source.

*******************************************************************************

Yes, we are using the source from https://github.com/rhboot/shim/releases/tag/15.8

*******************************************************************************
### URL for a repo that contains the exact code which was built to get this binary:
*******************************************************************************

https://github.com/gooroom/shim

*******************************************************************************
### What patches are being applied and why:
*******************************************************************************
- [block-grub-sbat3-debian.patch](https://github.com/gooroom/shim/blob/gooroom-3.0/debian/patches/block-grub-sbat3-debian.patch)

Debian's grub.3 update was broken - some binaries included the SBAT data update but not the security patches.

This patch denies loading binaries with `grub.debian,3`.

- [aarch64-shim-old.patch](https://github.com/gooroom/shim/blob/gooroom-3.0/debian/patches/aarch64-shim-old.patch)

shim 15.6 onwards needs newer binutils to build on aarch64. That works
better, but we don't have that binutils update in older Debian
releases. Undo the build changes here so that we can build for aarch64
on older stable releases. We're not going to sign them, but we need
the binaries for aarch64.

- [aarch64-gnuefi-old.patch](https://github.com/gooroom/shim/blob/gooroom-3.0/debian/patches/aarch64-gnuefi-old.patch)

The same reason as above.

- [Make-sbat_var.S-parse-right-with-buggy-gcc-binutils.patch](https://github.com/gooroom/shim/blob/gooroom-3.0/debian/patches/Make-sbat_var.S-parse-right-with-buggy-gcc-binutils.patch)

In https://github.com/rhboot/shim/issues/533 , iokomin noticed that
gas in binutils before 2.36 appears to be incorrectly concatenating
string literals in '.asciz' directives, including an extra NUL character
in between the strings, and this will cause us to incorrectly parse the 
.sbatlevel section in shim binaries.

This patch adds test cases that will cause the build to fail if this has 
happened, as well as changing sbat_var.S to to use '.ascii' and '.byte'
to construct the data, rather than using '.asciz'.

*******************************************************************************
### Do you have the NX bit set in your shim? If so, is your entire boot stack NX-compatible and what testing have you done to ensure such compatibility?

See https://techcommunity.microsoft.com/t5/hardware-dev-center/nx-exception-for-shim-community/ba-p/3976522 for more details on the signing of shim without NX bit.
*******************************************************************************
No we don't have NX bit.

*******************************************************************************
### If shim is loading GRUB2 bootloader what exact implementation of Secureboot in GRUB2 do you have? (Either Upstream GRUB2 shim_lock verifier or Downstream RHEL/Fedora/Debian/Canonical-like implementation)
*******************************************************************************

We have our own downstream implementation. We are also following on debian's patches and reflect these patches immediately

*******************************************************************************
### If shim is loading GRUB2 bootloader and your previously released shim booted a version of GRUB2 affected by any of the CVEs in the July 2020, the March 2021, the June 7th 2022, the November 15th 2022, or 3rd of October 2023 GRUB2 CVE list, have fixes for all these CVEs been applied?

* 2020 July - BootHole
  * Details: https://lists.gnu.org/archive/html/grub-devel/2020-07/msg00034.html
  * CVE-2020-10713
  * CVE-2020-14308
  * CVE-2020-14309
  * CVE-2020-14310
  * CVE-2020-14311
  * CVE-2020-15705
  * CVE-2020-15706
  * CVE-2020-15707
* March 2021
  * Details: https://lists.gnu.org/archive/html/grub-devel/2021-03/msg00007.html
  * CVE-2020-14372
  * CVE-2020-25632
  * CVE-2020-25647
  * CVE-2020-27749
  * CVE-2020-27779
  * CVE-2021-3418 (if you are shipping the shim_lock module)
  * CVE-2021-20225
  * CVE-2021-20233
* June 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-06/msg00035.html, SBAT increase to 2
  * CVE-2021-3695
  * CVE-2021-3696
  * CVE-2021-3697
  * CVE-2022-28733
  * CVE-2022-28734
  * CVE-2022-28735
  * CVE-2022-28736
  * CVE-2022-28737
* November 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-11/msg00059.html, SBAT increase to 3
  * CVE-2022-2601
  * CVE-2022-3775
* October 2023 - NTFS vulnerabilities
  * Details: https://lists.gnu.org/archive/html/grub-devel/2023-10/msg00028.html, SBAT increase to 4
  * CVE-2023-4693
  * CVE-2023-4692
*******************************************************************************

Our gooroom-grub was developed based on GRUB2 2.06 which is not affected by the CVEs.

*******************************************************************************
### If shim is loading GRUB2 bootloader, and if these fixes have been applied, is the upstream global SBAT generation in your GRUB2 binary set to 4?
The entry should look similar to: `grub,4,Free Software Foundation,grub,GRUB_UPSTREAM_VERSION,https://www.gnu.org/software/grub/`
*******************************************************************************

YES

*******************************************************************************
### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?
### Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?
*******************************************************************************
[your text here]

*******************************************************************************
### If your boot chain of trust includes a Linux kernel:
### Is upstream commit [1957a85b0032a81e6482ca4aab883643b8dae06e "efi: Restrict efivar_ssdt_load when the kernel is locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1957a85b0032a81e6482ca4aab883643b8dae06e) applied?
### Is upstream commit [75b0cea7bf307f362057cc778efe89af4c615354 "ACPI: configfs: Disallow loading ACPI tables when locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=75b0cea7bf307f362057cc778efe89af4c615354) applied?
### Is upstream commit [eadb2f47a3ced5c64b23b90fd2a3463f63726066 "lockdown: also lock down previous kgdb use"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eadb2f47a3ced5c64b23b90fd2a3463f63726066) applied?
*******************************************************************************
[your text here]

*******************************************************************************
### Do you build your signed kernel with additional local patches? What do they do?
*******************************************************************************
[your text here]

*******************************************************************************
### Do you use an ephemeral key for signing kernel modules?
### If not, please describe how you ensure that one kernel build does not load modules built for another kernel.
*******************************************************************************

We haven't used shim so far, so there is no such thing.
In our new chain of trust, we will not use old GRUB2 affected by CVEs, but use our groroom-grub based on GRUB2 2.06.

*******************************************************************************
### If you use vendor_db functionality of providing multiple certificates and/or hashes please briefly describe your certificate setup.
### If there are allow-listed hashes please provide exact binaries for which hashes are created via file sharing service, available in public with anonymous access for verification.
*******************************************************************************
We don't use vendor_db.

*******************************************************************************
### If you are re-using a previously used (CA) certificate, you will need to add the hashes of the previous GRUB2 binaries exposed to the CVEs to vendor_dbx in shim in order to prevent GRUB2 from being able to chainload those older GRUB2 binaries. If you are changing to a new (CA) certificate, this does not apply.
### Please describe your strategy.
*******************************************************************************
This is our first submission. We created the first (CA) certificate.

*******************************************************************************
### What OS and toolchain must we use to reproduce this build?  Include where to find it, etc.  We're going to try to reproduce your build as closely as possible to verify that it's really a build of the source tree you tell us it is, so these need to be fairly thorough. At the very least include the specific versions of gcc, binutils, and gnu-efi which were used, and where to find those binaries.
### If the shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case and what the differences would be.
*******************************************************************************
Dockerfile is provided to reproduce this build

*******************************************************************************
### Which files in this repo are the logs for your build?
This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.
*******************************************************************************
https://github.com/ozun215/shim-review-1/blob/15.8-gooroom-3.0/build.log

*******************************************************************************
### What changes were made in the distor's secure boot chain since your SHIM was last signed?
For example, signing new kernel's variants, UKI, systemd-boot, new certs, new CA, etc..
*******************************************************************************
No changes. This is our first shim to receive the signature from MS.

*******************************************************************************
### What is the SHA256 hash of your final SHIM binary?
*******************************************************************************

7fb5db43feb7a0ade8bedd573eb044cede248501000865db2cb5745d2695ccea

*******************************************************************************
### How do you manage and protect the keys used in your SHIM?
*******************************************************************************

The keys are kept in USB HSM that is under physical access control.

*******************************************************************************
### Do you use EV certificates as embedded certificates in the SHIM?
*******************************************************************************
No

*******************************************************************************
### Do you add a vendor-specific SBAT entry to the SBAT section in each binary that supports SBAT metadata ( GRUB2, fwupd, fwupdate, systemd-boot, systemd-stub, shim + all child shim binaries )?
### Please provide exact SBAT entries for all shim binaries as well as all SBAT binaries that shim will directly boot.
### Where your code is only slightly modified from an upstream vendor's, please also preserve their SBAT entries to simplify revocation.
If you are using a downstream implementation of GRUB2 or systemd-boot (e.g.
from Fedora or Debian), please preserve the SBAT entry from those distributions
and only append your own. More information on how SBAT works can be found
[here](https://github.com/rhboot/shim/blob/main/SBAT.md).
*******************************************************************************
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md   
shim,3,UEFI shim,shim,1,https://github.com/rhboot/shim   
shim.gooroom,1,Gooroom,shim,15.7~deb11u1+grm3u1,https://github.com/gooroom/shim   

sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md   
grub,4,Free Software Foundation,grub,2.06,https://www.gnu.org/software/grub/   
grub.debian,4,Debian,grub2,2.06-3~deb11u5,https://tracker.debian.org/pkg/grub2   
grub.gooroom,1,Gooroom,gooroom-grub,2.06-3+grm3u5,https://github.com/gooroom/gooroom-grub   

sbat,1,UEFI shim,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md   
fwupd,1,Firmware update daemon,fwupd,1.5.7,https://github.com/fwupd/fwupd   
fwupd.gooroom,1,Gooroom,fwupd,1.5.7-4+grm3u1,https://github.com/gooroom/fwupd   

*******************************************************************************
### If shim is loading GRUB2 bootloader, which modules are built into your signed GRUB2 image?
*******************************************************************************
boot part_gpt part_msdos fat ext2 normal configfile lspci ls reboot datetime time loadenv search help gfxmenu gfxterm gfxterm_menu gfxterm_background all_video png gettext linuxefi gcry_rsa test echo squash4 iso9660 exfat cpio_be cpio crypto gcry_sha256 gcry_sha512 tpm

*******************************************************************************
### If you are using systemd-boot on arm64 or riscv, is the fix for [unverified Devicetree Blob loading](https://github.com/systemd/systemd/security/advisories/GHSA-6m6p-rjcq-334c) included?
*******************************************************************************
https://github.com/gooroom/gooroom-grub, the full version number of our gooroom-grub is 2.06-3+grm3u5.
It is derived from the Debian Bullseye upstream 2.06-3 release with a number of patches applied - see debian/patches there.)

*******************************************************************************
### What is the origin and full version number of your bootloader (GRUB2 or systemd-boot or other)?
*******************************************************************************
???


*******************************************************************************
### If your SHIM launches any other components, please provide further details on what is launched.
*******************************************************************************
It launches fwupd.

*******************************************************************************
### If your GRUB2 or systemd-boot launches any other binaries that are not the Linux kernel in SecureBoot mode, please provide further details on what is launched and how it enforces Secureboot lockdown.
*******************************************************************************
None - it only launches a signed kernel in SecureBoot mode.

*******************************************************************************
### How do the launched components prevent execution of unauthenticated code?
*******************************************************************************
We are following on "Debian 11"

-- See below of Debian 11's

Debian's signed Linux packages have a common set of lockdown patches.
Debian's signed grub2 packages include common secure boot patches so they will only load appropriately signed binaries.

*******************************************************************************
### Does your SHIM load any loaders that support loading unsigned kernels (e.g. GRUB2)?
*******************************************************************************
N/A

*******************************************************************************
### What kernel are you using? Which patches does it includes to enforce Secure Boot?
*******************************************************************************
Debian linux kernel(v5.10.136-1)

*******************************************************************************
### Add any additional information you think we may need to validate this shim.
*******************************************************************************
N/A
