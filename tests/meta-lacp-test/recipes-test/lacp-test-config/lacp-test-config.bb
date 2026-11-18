SUMMARY = "lacp-takeoverd test environment"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

SRC_URI = " \
    file://10-eth0.network \
    file://10-eth1.network \
    file://lacp-takeover.conf \
"
S = "${UNPACKDIR}"

inherit allarch

LACP_TEST_PUBKEY ??= ""

do_install() {
    install -d ${D}${sysconfdir}/systemd/network ${D}${sysconfdir}/systemd/system/xyz.openbmc_project.Network.service.d
    install -m 0644 ${S}/10-* ${D}${sysconfdir}/systemd/network/
    install -m 0644 ${S}/lacp-takeover.conf ${D}${sysconfdir}/lacp-takeover.conf
    printf '[Unit]\nConditionPathExists=/nonexistent\n' > \
        ${D}${sysconfdir}/systemd/system/xyz.openbmc_project.Network.service.d/disable.conf
    install -d -m 0700 ${D}/home/root/.ssh
    echo "${LACP_TEST_PUBKEY}" > ${D}/home/root/.ssh/authorized_keys
    chmod 0600 ${D}/home/root/.ssh/authorized_keys
}

FILES:${PN} = "${sysconfdir} /home/root"
