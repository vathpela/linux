#!/bin/bash
#
# run-qemu-eml.sh
# Copyright 2019 Peter Jones <pjones@redhat.com>
#

set -eu

tapnum=${RANDOM}

cleanup() {
    set +e
    while sudo umount eml 2>/dev/null ; do
        :;
    done
    rmdir eml 2>/dev/null
    # shellcheck disable=SC2034
    sudo losetup -l | grep -v ^NAME | while read -r dev b c d e file f g ; do
        if [ "${file}" == "$PWD/eml.img" ]; then
            for x in /dev/mapper/"${dev}"p* ; do
                if [ -e "${x}" ]; then
                    sudo dmsetup remove "${x}" 2>/dev/null || :
                fi
            done
            sudo losetup -d "${dev}"
        fi
    done
    sudo brctl delif virbr0 vnet${tapnum}
    sudo ip link set vnet${tapnum} down
    sudo ip tuntap del vnet${tapnum} mode tap

    rm -f eml.img eml_VARS.fd
}

fatal() {
    cleanup
    exit 1
}

trap fatal ERR INT TRAP ABRT HUP TERM

size() {
    stat -c '%s' "${1}"
}

blksize() {
    stat -c '%B' "${1}"
}

div() {
    echo "${1} / ${2}" | bc -q
}

mod() {
    echo "${1} % ${2}" | bc -q
}

mul () {
    echo "${1} * ${2}" | bc -q
}

add() {
    echo "${1} + ${2}" | bc -q
}

sub() {
    echo "${1} - ${2}" | bc -q
}

align_up() {
    local m
    m=$(mod "${1}" "${2}")
    local d
    d=$(div "${1}" "${2}")

    local sz
    sz=$(mul "${d}" "${2}")
    if [ "${m}" != "0" ] ; then
        local addend
        addend=$(sub "${2}" "${m}")
        sz=$(add "${sz}" "${addend}")
    fi
    echo "${sz}"
}

assert_exists() {
    if [ ! -f "${1}" ] ; then
        echo "${1}: no such file or directory."
        exit 1
    fi
}

assert_exists arch/x86/boot/bzImage
assert_exists /usr/share/OVMF/OVMF_CODE.fd
assert_exists /usr/share/OVMF/OVMF_VARS.fd
assert_exists /usr/share/OVMF/UefiShell.iso

cp /usr/share/OVMF/OVMF_VARS.fd eml_VARS.fd

imgsize="$(add "$(align_up "$(align_up "$(size arch/x86/boot/bzImage)" "$(blksize arch/x86/boot/bzImage)")" 4194304)" 2097152)"
if [ -f initramfs.cpio.gz ]; then
    initramfs=initramfs.cpio.gz
    initrdsz="$(add "$(align_up "$(align_up "$(size $initramfs)" "$(blksize $initramfs)")" 4194304)" 2097152)"
    imgsize="$(add "${imgsize}" "${initrdsz}")"
else
    initramfs="" || :
fi
qemu-img create -f raw eml.img "${imgsize}" >/dev/null
cat <<EOF | parted eml.img >/dev/null 2>&1
unit b
mklabel gpt
mkpart "EFI System Partition" fat32 1MiB $(sub "${imgsize}" 17280)
set 1 boot on
EOF

# shellcheck disable=SC2034
part=$(sudo kpartx -a -v -p p eml.img | while read -r a b c d ; do echo "${c}" ; break ; done)
sudo mkfs.vfat "/dev/mapper/${part}" >/dev/null
mkdir eml
sudo mount -o uid="${UID}" "/dev/mapper/${part}" eml
cp arch/x86/boot/bzImage eml/
if [ -f initramfs.cpio.gz ]; then
    cp initramfs.cpio.gz eml/
    initramfs="initrd=${initramfs}"
fi
dyndbg=''
for x in \
	'drivers/firmware/*' '*kexec*' 'arch/x86/platform/efi/*'
do
        dyndbg="${dyndbg} dyndbg=\"file ${x} +pflm\""
done
opts='efi=debug boot_delay=0 ignore_loglevel=Y'

cat <<EOF | iconv -t 'UCS-2LE' | unix2dos -ul -u -m > eml/startup.nsh
fs1:bzImage console=ttyS0 console=tty0 earlyprintk=efi,serial efi=debug ${initramfs} root=/dev/root ${dyndbg} ${opts}
EOF
sudo umount eml
rmdir eml
sudo dmsetup remove "${part}"
truncate -s 0 eml.tty.log eml.screen.tty.log eml.log

sudo ip tuntap add dev vnet${tapnum} mode tap vnet_hdr
sudo brctl addif virbr0 vnet${tapnum}

sudo ip link set vnet${tapnum} up
sudo ip link set virbr0 up

strace -o /home/pjones/devel/kernel.org/linux/efi-mode-linux/rqe.strace -v -f -s1024 -tt qemu-system-x86_64 \
    -machine accel=kvm \
    -name guest=efi-mode-linux,debug-threads=on \
    -machine pc-q35-2.10,accel=kvm,usb=off,vmport=off,smm=on,dump-guest-core=off \
    -cpu Skylake-Client \
    -global driver=cfi.pflash01,property=secure,value=on \
    -drive file=/usr/share/OVMF/OVMF_CODE.fd,if=pflash,format=raw,unit=0,readonly=on \
    -drive file="$PWD/eml_VARS.fd",if=pflash,format=raw,unit=1 \
    -m 2048 \
    -overcommit mem-lock=off \
    -smp 1,sockets=1,cores=1,threads=1 \
    -no-user-config -nodefaults \
    -rtc base=utc,driftfix=slew -global kvm-pit.lost_tick_policy=delay \
    -no-shutdown \
    -global ICH9-LPC.disable_s3=1 \
    -global ICH9-LPC.disable_s4=1 \
    -boot strict=on \
    -device pcie-root-port,port=0x10,chassis=1,id=pci.1,bus=pcie.0,multifunction=on,addr=0x2 \
    -device pcie-root-port,port=0x11,chassis=2,id=pci.2,bus=pcie.0,addr=0x2.0x1 \
    -device pcie-root-port,port=0x12,chassis=3,id=pci.3,bus=pcie.0,addr=0x2.0x2 \
    -device pcie-root-port,port=0x13,chassis=4,id=pci.4,bus=pcie.0,addr=0x2.0x3 \
    -device pcie-root-port,port=0x14,chassis=5,id=pci.5,bus=pcie.0,addr=0x2.0x4 \
    -device pcie-root-port,port=0x15,chassis=6,id=pci.6,bus=pcie.0,addr=0x2.0x5 \
    -device pcie-root-port,port=0x16,chassis=7,id=pci.7,bus=pcie.0,addr=0x2.0x6 \
    -device ich9-usb-ehci1,id=usb,bus=pcie.0,addr=0x1d.0x7 \
    -device ich9-usb-uhci1,masterbus=usb.0,firstport=0,bus=pcie.0,multifunction=on,addr=0x1d \
    -device ich9-usb-uhci2,masterbus=usb.0,firstport=2,bus=pcie.0,addr=0x1d.0x1 \
    -device ich9-usb-uhci3,masterbus=usb.0,firstport=4,bus=pcie.0,addr=0x1d.0x2 \
    -device virtio-serial-pci,id=virtio-serial0,bus=pci.2,addr=0x0 \
    -drive file="$PWD/eml.img",format=raw,if=none,id=drive-virtio-disk0 \
    -device virtio-blk-pci,scsi=off,bus=pci.3,addr=0x0,drive=drive-virtio-disk0,id=virtio-disk0,bootindex=2 \
    -drive file=/usr/share/OVMF/UefiShell.iso,format=raw,if=none,id=drive-sata0-0-0,media=cdrom,readonly=on \
    -device ide-cd,bus=ide.0,drive=drive-sata0-0-0,id=sata0-0-0,bootindex=1 \
    -device qxl-vga,id=video0,ram_size=67108864,vram_size=67108864,vram64_size_mb=0,vgamem_mb=16,max_outputs=1,bus=pcie.0,addr=0x1 \
    -device virtio-balloon-pci,id=balloon0,bus=pci.5,addr=0x0 \
    -object rng-random,id=objrng0,filename=/dev/urandom \
    -device virtio-rng-pci,rng=objrng0,id=rng0,bus=pci.6,addr=0x0 \
    -sandbox off \
    -sandbox elevateprivileges=off \
    -sandbox obsolete=off \
    -sandbox spawn=off \
    -sandbox resourcecontrol=off \
    -msg timestamp=on \
    -chardev pty,id=charserial0 \
    -device isa-serial,chardev=charserial0,id=serial0 \
    -serial file:eml.tty.log \
    -chardev pty,id=charserial1 \
    -device isa-serial,chardev=charserial1,id=serial1 \
    -netdev tap,id=vnet0,ifname=vnet${tapnum},br=virbr0,script=no,downscript=no \
    -device virtio-net-pci,netdev=vnet0,id=vnet0,mac=52:54:00:a3:ae:38,bus=pci.7,addr=0x0 \
    -s

if command -v untty >/dev/null 2>&1 ; then
    untty eml.tty.log > eml.log
fi

cleanup

# 19657 ?        Sl     0:09 /usr/bin/qemu-system-x86_64 -machine accel=kvm -name guest=baytrail-x64-sb,debug-threads=on -S -object secret,id=masterKey0,format=raw,file=/var/lib/libvirt/qemu/domain-2-baytrail-x64-sb/master-key.aes -machine pc-q35-2.10,accel=kvm,usb=off,vmport=off,smm=on,dump-guest-core=off -cpu Skylake-Client -global driver=cfi.pflash01,property=secure,value=on -drive file=/usr/share/OVMF/OVMF_CODE.secboot.fd,if=pflash,format=raw,unit=0,readonly=on -drive file=/var/lib/libvirt/qemu/nvram/baytrail-x64-sb_VARS.fd,if=pflash,format=raw,unit=1 -m 2048 -realtime mlock=off -smp 1,sockets=1,cores=1,threads=1 -uuid 03d5a917-c553-480c-a88b-4ffe2aa341a3 -no-user-config -nodefaults -chardev socket,id=charmonitor,fd=25,server,nowait -mon chardev=charmonitor,id=monitor,mode=control -rtc base=utc,driftfix=slew -global kvm-pit.lost_tick_policy=delay -no-hpet -no-shutdown -global ICH9-LPC.disable_s3=1 -global ICH9-LPC.disable_s4=1 -boot strict=on -device pcie-root-port,port=0x10,chassis=1,id=pci.1,bus=pcie.0,multifunction=on,addr=0x2 -device pcie-root-port,port=0x11,chassis=2,id=pci.2,bus=pcie.0,addr=0x2.0x1 -device pcie-root-port,port=0x12,chassis=3,id=pci.3,bus=pcie.0,addr=0x2.0x2 -device pcie-root-port,port=0x13,chassis=4,id=pci.4,bus=pcie.0,addr=0x2.0x3 -device pcie-root-port,port=0x14,chassis=5,id=pci.5,bus=pcie.0,addr=0x2.0x4 -device pcie-root-port,port=0x15,chassis=6,id=pci.6,bus=pcie.0,addr=0x2.0x5 -device ich9-usb-ehci1,id=usb,bus=pcie.0,addr=0x1d.0x7 -device ich9-usb-uhci1,masterbus=usb.0,firstport=0,bus=pcie.0,multifunction=on,addr=0x1d -device ich9-usb-uhci2,masterbus=usb.0,firstport=2,bus=pcie.0,addr=0x1d.0x1 -device ich9-usb-uhci3,masterbus=usb.0,firstport=4,bus=pcie.0,addr=0x1d.0x2 -device virtio-serial-pci,id=virtio-serial0,bus=pci.2,addr=0x0 -drive file=/var/lib/libvirt/images/baytrail.qcow2,format=qcow2,if=none,id=drive-virtio-disk0 -device virtio-blk-pci,scsi=off,bus=pci.3,addr=0x0,drive=drive-virtio-disk0,id=virtio-disk0,bootindex=2 -drive file=/home/pjones/Downloads/qxl.iso,format=raw,if=none,id=drive-sata0-0-0,media=cdrom,readonly=on -device ide-cd,bus=ide.0,drive=drive-sata0-0-0,id=sata0-0-0,bootindex=1 -netdev tap,fd=27,id=hostnet0,vhost=on,vhostfd=28 -device virtio-net-pci,netdev=hostnet0,id=net0,mac=52:54:00:4c:26:70,bus=pci.1,addr=0x0 -chardev pty,id=charserial0 -device isa-serial,chardev=charserial0,id=serial0 -chardev socket,id=charchannel0,fd=29,server,nowait -device virtserialport,bus=virtio-serial0.0,nr=1,chardev=charchannel0,id=channel0,name=org.qemu.guest_agent.0 -chardev spicevmc,id=charchannel1,name=vdagent -device virtserialport,bus=virtio-serial0.0,nr=2,chardev=charchannel1,id=channel1,name=com.redhat.spice.0 -device usb-tablet,id=input0,bus=usb.0,port=1 -spice port=5900,addr=127.0.0.1,disable-ticketing,image-compression=off,seamless-migration=on -device qxl-vga,id=video0,ram_size=67108864,vram_size=67108864,vram64_size_mb=0,vgamem_mb=16,max_outputs=1,bus=pcie.0,addr=0x1 -chardev spicevmc,id=charredir0,name=usbredir -device usb-redir,chardev=charredir0,id=redir0,bus=usb.0,port=2 -chardev spicevmc,id=charredir1,name=usbredir -device usb-redir,chardev=charredir1,id=redir1,bus=usb.0,port=3 -device virtio-balloon-pci,id=balloon0,bus=pci.4,addr=0x0 -object rng-random,id=objrng0,filename=/dev/urandom -device virtio-rng-pci,rng=objrng0,id=rng0,bus=pci.5,addr=0x0 -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny -msg timestamp=on

# vim:fenc=utf-8:tw=75:noai:nosi:noci
