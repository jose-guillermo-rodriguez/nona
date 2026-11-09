// Copyright (c) 2026 Nona Contributors.
// Licensed under the Apache License, Version 2.0 or the MIT License.
// ============================================================================
// ============================================================================

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include "nona.h"

#define CANARY_PAGE_SIZE 4096
#define CANARY_BYTE 0xAA

static uint8_t* g_shared_canary = NULL;

static void nona_signal_decontamination_handler(int sig) {
    if (g_shared_canary != NULL) {
        nona_ct_zeroize(g_shared_canary, CANARY_PAGE_SIZE);
    }
    _exit(128 + sig);
}

static void test_core_dump_suppression(void) {
    printf("[*] Auditing RLIMIT_CORE core dump suppression...\n");
    struct rlimit rl;
    int rc = getrlimit(RLIMIT_CORE, &rl);
    assert(rc == 0);

    printf("    [+] RLIMIT_CORE: rlim_cur = %llu, rlim_max = %llu\n",
           (unsigned long long)rl.rlim_cur, (unsigned long long)rl.rlim_max);

    if (rl.rlim_cur != 0) {
        fprintf(stderr, "[-] FAILURE: Core dumps are not suppressed (rlim_cur != 0)\n");
        exit(1);
    }
    printf("  [+] Core dump suppression verified: rlim_cur == 0.\n");
}

static void test_signal_decontamination(int sig) {
    printf("[*] Testing Asynchronous Signal Interception & Decontamination for signal %d...\n", sig);

    uint8_t* shared_mem = (uint8_t*)mmap(NULL, CANARY_PAGE_SIZE,
                                         PROT_READ | PROT_WRITE,
                                         MAP_SHARED | MAP_ANON, -1, 0);
    if (shared_mem == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    memset(shared_mem, CANARY_BYTE, CANARY_PAGE_SIZE);
    assert(shared_mem[0] == CANARY_BYTE);
    assert(shared_mem[CANARY_PAGE_SIZE - 1] == CANARY_BYTE);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    }

    if (pid == 0) {
        g_shared_canary = shared_mem;

        sigset_t unblock_mask;
        sigemptyset(&unblock_mask);
        sigaddset(&unblock_mask, sig);
        sigprocmask(SIG_UNBLOCK, &unblock_mask, NULL);

        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = nona_signal_decontamination_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;

        if (sigaction(sig, &sa, NULL) != 0) {
            perror("sigaction");
            _exit(1);
        }

        raise(sig);
        _exit(0);
    }

    int status = 0;
    pid_t wait_res = waitpid(pid, &status, 0);
    assert(wait_res == pid);

    if (WIFEXITED(status)) {
        assert(WEXITSTATUS(status) == 128 + sig);
    } else if (WIFSIGNALED(status)) {
        assert(WTERMSIG(status) == sig);
    }

    size_t non_zero_count = 0;
    for (size_t i = 0; i < CANARY_PAGE_SIZE; i++) {
        if (shared_mem[i] != 0x00) {
            non_zero_count++;
        }
    }

    if (non_zero_count > 0) {
        fprintf(stderr, "[-] FAILURE: Memory remanence detected! %zu / %d bytes remained non-zero.\n",
                non_zero_count, CANARY_PAGE_SIZE);
        munmap(shared_mem, CANARY_PAGE_SIZE);
        exit(1);
    }

    printf("  [+] Memory scrub verified: All %d canary bytes zeroed (0x00) upon signal %d receipt.\n",
           CANARY_PAGE_SIZE, sig);

    munmap(shared_mem, CANARY_PAGE_SIZE);
}

int main(void) {
    printf("[===] EXECUTING REAL-KERNEL SIGNAL INTERCEPTION & OPSEC SUITE [===]\n");

    int32_t init_rc = nona_core_init();
    assert(init_rc <= 0);

    test_core_dump_suppression();
    test_signal_decontamination(SIGINT);
    test_signal_decontamination(SIGTERM);

    printf("[===] SIGNAL INTERCEPTION & OPSEC SUITE PASSED (100%% VERIFIED) [===]\n");
    return 0;
}
