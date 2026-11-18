SUMMARY = "BMC LACP takeover daemon"
LICENSE = "BSD-2-Clause"
LIC_FILES_CHKSUM = "file://LICENSE;md5=3d51671892b5725d153c5bac343ebee0"

FILESEXTRAPATHS:prepend := "${THISDIR}/../../../..:"
SRC_URI = " \
    file://LICENSE \
    file://Makefile \
    file://lacp-takeoverd.c \
    file://lacp-pdu.h \
    file://lacp-watchdog.h \
    file://net-common.c \
    file://net-common.h \
    file://init/lacp-takeoverd.service \
    file://conf/00-bmc-bond0.netdev \
    file://conf/00-bmc-bond0.network \
"
S = "${UNPACKDIR}"

DEPENDS = "libpcap systemd"

inherit systemd

SYSTEMD_SERVICE:${PN} = "lacp-takeoverd.service"

do_compile() {
    oe_runmake lacp-takeoverd
}

do_install() {
    install -Dm 0755 lacp-takeoverd ${D}/usr/sbin/lacp-takeoverd
    install -Dm 0644 init/lacp-takeoverd.service ${D}${systemd_system_unitdir}/lacp-takeoverd.service
    install -Dm 0644 -t ${D}${sysconfdir}/systemd/network conf/00-bmc-bond0.netdev conf/00-bmc-bond0.network
}

FILES:${PN} += "/usr/sbin ${sysconfdir}/systemd/network"
