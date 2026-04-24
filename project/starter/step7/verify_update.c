#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define ROOT_CA_PATH "../step6/rootCA.crt"
#define UPDATE_CERT_PATH "client_unzipped/software_update.crt"
#define UPDATE_SIG_PATH "client_unzipped/software_update.sig"
#define UPDATE_BIN_PATH "client_unzipped/software_update.bin"
#define UPDATE_CHECKSUM_PATH "client_unzipped/software_update.checksum"

static int run_cmd(const char *cmd) {
    int rc = system(cmd);
    if (rc == -1) {
        return 0;
    }

    if (!WIFEXITED(rc)) {
        return 0;
    }

    return WEXITSTATUS(rc) == 0;
}

int main(void) {
    const char *pubkey_tmp = "/tmp/software_update_pubkey.pem";
    char cmd[1024];

    snprintf(
        cmd,
        sizeof(cmd),
        "openssl verify -CAfile %s %s > /dev/null 2>&1",
        ROOT_CA_PATH,
        UPDATE_CERT_PATH
    );
    if (!run_cmd(cmd)) {
        printf("0\n");
        return 0;
    }

    snprintf(
        cmd,
        sizeof(cmd),
        "openssl x509 -in %s -pubkey -noout > %s 2>/dev/null",
        UPDATE_CERT_PATH,
        pubkey_tmp
    );
    if (!run_cmd(cmd)) {
        printf("0\n");
        return 0;
    }

    snprintf(
        cmd,
        sizeof(cmd),
        "openssl dgst -sha256 -verify %s -signature %s %s > /dev/null 2>&1",
        pubkey_tmp,
        UPDATE_SIG_PATH,
        UPDATE_BIN_PATH
    );
    if (!run_cmd(cmd)) {
        unlink(pubkey_tmp);
        printf("0\n");
        return 0;
    }

    unlink(pubkey_tmp);

    snprintf(
        cmd,
        sizeof(cmd),
        "(cd client_unzipped && sha256sum -c software_update.checksum) > /dev/null 2>&1"
    );
    if (!run_cmd(cmd)) {
        printf("0\n");
        return 0;
    }

    printf("1\n");
    return 1;
}
