# `ibmswtpm2`

[The `ibmswtpm2` project](https://sourceforge.net/projects/ibmswtpm2) is a TPM 2.0 simulator. `tpm2-abrmd` can be configured to use it as a backend instead of a real TPM at `/dev/tpm0`. This document describes how to compile and set up the simulator on Ubuntu 18.04.

Note: It's expected you've already followed the steps in [`index.md`](index.md) to compile `tpm2-abrmd`.

1. Compile and start `/usr/local/bin/tpm_server`

    ```sh
    sudo apt install \
        curl gcc make patch tar \
        libssl-dev

    mkdir -p ~/src
    cd ~/src

    curl -Lo ibmtpm1637.tar.gz 'https://sourceforge.net/projects/ibmswtpm2/files/ibmtpm1637.tar.gz'
    tar x --one-top-level=ibmtpm1637 -f ibmtpm1637.tar.gz
    cd ibmtpm1637/

    # Patches taken from OpenSUSE's ibmswtpm2 package
    #
    # https://build.opensuse.org/package/show/security/ibmswtpm2

    # makefile.patch
    patch -p1 -i - <<-EOF
    --- ibmswtpm2-1637.orig/src/makefile	2019-12-19 23:35:43.000000000 +0100
    +++ ibmswtpm2-1637/src/makefile	2020-08-17 18:56:34.607550789 +0200
    @@ -40,10 +40,10 @@

     CC = /usr/bin/gcc

    -CCFLAGS = -Wall  			\\
    +CCFLAGS += -fno-strict-aliasing -fno-aggressive-loop-optimizations -Wno-unused-result \\
     	-Wmissing-declarations -Wmissing-prototypes -Wnested-externs \\
    -	-Werror -Wsign-compare \\
    -	 -c -ggdb -O0 			\\
    +	-Werror -Wsign-compare -Wno-unused-value -Wno-aggressive-loop-optimizations \\
    +	 -c -ggdb			\\
     	-DTPM_POSIX			\\
     	-D_POSIX_			\\
     	-DTPM_NUVOTON
    @@ -54,7 +54,7 @@
     #	--coverage			\\
     #	-fprofile-arcs -ftest-coverage

    -LNFLAGS = -ggdb 			\\
    +LNFLAGS += -ggdb 			\\
     	-lcrypto			\\
     	-lpthread			\\
     	-lrt				\\

    EOF

    # ibmswtpm2-TcpServerPosix-Fix-use-of-uninitialized-value.patch
    patch -p1 -i - <<-EOF
    From 03efa66788ca4828392664c4f6123ad4f190c865 Mon Sep 17 00:00:00 2001
    From: Michal Suchanek <msuchanek@suse.de>
    Date: Mon, 17 Aug 2020 19:28:51 +0200
    Subject: [PATCH] TcpServerPosix: Fix use of uninitialized value.

    ReadUINT32 does not modify the output when it fails. Do not use the
    output in that case.

    Signed-off-by: Michal Suchanek <msuchanek@suse.de>
    ---
     src/TcpServerPosix.c | 3 ++-
     1 file changed, 2 insertions(+), 1 deletion(-)

    diff --git a/src/TcpServerPosix.c b/src/TcpServerPosix.c
    index 20fcb29352a2..5bcc47aaeac7 100644
    --- a/src/TcpServerPosix.c
    +++ b/src/TcpServerPosix.c
    @@ -278,7 +278,8 @@ PlatformServer(
     		      {
     			  UINT32 actHandle;
     			  ok = ReadUINT32(s, &actHandle);
    -			  WriteUINT32(s, _rpc__ACT_GetSignaled(actHandle));
    +			  if(ok)
    +			      WriteUINT32(s, _rpc__ACT_GetSignaled(actHandle));
     			  break;
     		      }
     		  default:
    --
    2.26.2
    EOF

    # ibmswtpm2-NVDynamic-Fix-use-of-uninitialized-value.patch
    patch -p1 -i - <<-EOF
    diff -ur ibmswtpm2-1637.orig/src/NVDynamic.c ibmswtpm2-1637/src/NVDynamic.c
    --- ibmswtpm2-1637.orig/src/NVDynamic.c	2020-03-26 23:15:48.000000000 +0100
    +++ ibmswtpm2-1637/src/NVDynamic.c	2020-08-20 16:37:09.481920068 +0200
    @@ -122,7 +122,7 @@
     	    if(HandleGetType(nvHandle) == type)
     		break;
     	}
    -    if(handle != NULL)
    +    if(addr && (handle != NULL))
     	*handle = nvHandle;
         return addr;
     }
    Only in ibmswtpm2-1637/src: NVDynamic.c~
    EOF


    cd src/
    make "-j$(nproc)"

    mkdir -p /usr/local/bin
    sudo cp ./tpm_server /usr/local/bin/tpm_server

    sudo mkdir -p /var/lib/ibmswtpm2
    sudo chown "$(id -u tss):$(id -g tss)" /var/lib/ibmswtpm2


    sudo mkdir -p /etc/systemd/system/
    sudo tee /etc/systemd/system/ibmswtpm2.service <<-EOF
    [Unit]
    Description=IBM's Software TPM 2.0

    [Service]
    ExecStart=/usr/local/bin/tpm_server
    WorkingDirectory=/var/lib/ibmswtpm2
    User=tss
    EOF
    sudo systemctl daemon-reload
    sudo systemctl start ibmswtpm2
    ```


1. Configure `tpm2-abrmd` to use the `mssim` TCTI and start it.

    ```sh
    sudo mkdir -p /etc/systemd/system/tpm2-abrmd.service.d/
    sudo tee /etc/systemd/system/tpm2-abrmd.service.d/mssim.conf <<-EOF
    [Unit]
    ConditionPathExistsGlob=
    Requires=ibmswtpm2.service
    After=ibmswtpm2.service

    [Service]
    ExecStart=
    ExecStart=/usr/local/sbin/tpm2-abrmd --tcti=mssim
    EOF

    sudo systemctl daemon-reload
    sudo systemctl restart tpm2-abrmd
    ```

1. Verify that everything is working.

    ```sh
    sudo systemctl status ibmswtpm2   # Should be active (running)
    sudo systemctl status tpm2-abrmd   # Should be active (running), and its log should say "tcti_conf after: "mssim""

    tpm2_pcrread sha256   # Should print a large array of bytes instead of an error like "ERROR: Esys_GetCapability(0xA000A) - tcti:IO failure"
    ```
