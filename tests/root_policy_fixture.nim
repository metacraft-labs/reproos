## The smallest tree ``tools/reproos_image_metadata.py`` will describe.
##
## ``recipes/reproos-image/scripts/build-verity-root.sh`` carries the guest
## inode policy into every root image it makes, and refuses to take a root
## hash over an image it could not describe. So a gate that drives the
## SHIPPED builder has to hand it a tree that is a root filesystem and not
## just a directory: the policy needs ``/etc/passwd`` to know who owns a
## home, ``/usr/bin/sudo`` to know what gets the setuid bit, and
## ``/etc/sudoers`` + ``/etc/sudo.conf`` to know what must stay
## unwritable.
##
## Three gates need that shape only so that the builder will accept their
## fixture at all, and it is written here ONCE for them. A second copy
## would be a second idea of what a ReproOS root minimally is, and the
## first time the policy grew a requirement only one of them would have
## been updated.
##
## ``tests/test_attested_root_metadata.nim`` deliberately does NOT use
## this, and that is worth knowing rather than glossing: it is the gate
## that owns the policy's answers, so its root is built to exercise them
## -- symlinks, a name with a space in it, a home to leave alone, enough
## content for a multi-level hash tree -- and its modes are chosen to be
## wrong in specific ways. Widening this fixture to that shape would make
## every gate that only needs a root filesystem pay for it, and would
## make a change to one gate's tree a change to the other three's images.
##
## Deliberately NOT a mock: nothing here stands in for the code under
## test. It is the same kind of fixture the gates already build -- real
## files on a real filesystem, imaged by the real ``mkfs.ext4`` and
## policed by the shipped policy.

import std/os

const
  PolicyFixtureUser* = "repro"
    ## The unprivileged account the fixture declares. Its home is the one
    ## tree the policy does NOT reassign to ``0:0``, so a gate that wants
    ## to check that exception has a name to look for.
  PolicyFixtureUid* = 1000
  PolicyFixtureGid* = 100

proc writeRootPolicyFixture*(dir: string; withHome = true) =
  ## Add the files the guest inode policy needs to an existing tree.
  ##
  ## Modes are deliberately the WRONG ones -- ``/usr/bin/sudo`` without
  ## its setuid bit, ``/etc/sudoers`` group-readable, ``/etc/sudo.conf``
  ## world-writable -- so that an image built from this tree only reaches
  ## the policy's answers if the policy actually ran.
  for d in ["etc", "usr/bin", "home"]:
    createDir(dir / d)
  writeFile(dir / "etc/passwd",
    "root:x:0:0::/root:/bin/sh\n" &
    PolicyFixtureUser & ":x:" & $PolicyFixtureUid & ":" & $PolicyFixtureGid &
    "::/home/" & PolicyFixtureUser & ":/bin/sh\n")
  writeFile(dir / "usr/bin/sudo", "#!/bin/sh\necho sudo-placeholder\n")
  setFilePermissions(dir / "usr/bin/sudo",
    {fpUserRead, fpUserWrite, fpUserExec,
     fpGroupRead, fpGroupExec, fpOthersRead, fpOthersExec})
  writeFile(dir / "etc/sudoers", "root ALL=(ALL) ALL\n")
  setFilePermissions(dir / "etc/sudoers",
    {fpUserRead, fpUserWrite, fpGroupRead})
  writeFile(dir / "etc/sudo.conf", "Plugin sudoers_policy sudoers.so\n")
  setFilePermissions(dir / "etc/sudo.conf",
    {fpUserRead, fpUserWrite, fpGroupRead, fpGroupWrite,
     fpOthersRead, fpOthersWrite})
  if withHome:
    createDir(dir / "home" / PolicyFixtureUser)
    writeFile(dir / "home" / PolicyFixtureUser / "profile",
      "# fixture home file\n")
