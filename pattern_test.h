#include "pattern.c" // get_prefix_ranges is a static function in pattern.c, can't introduce it by linking pattern.o
char ticker[10];  // Fix link issue: Undefined symbols for architecture x86_64: "_ticker"

START_TEST(test_get_prefix_ranges)
{
    struct {
        int addrtype;
        const char* pattern;
        const char* result_0;
        const char* result_1;
    } tests[] = {
        { 0,
          "12",
          "0AF820335D9B3D9CF58B911D87035677FB7F528100000000",
          "15F04066BB367B39EB17223B0E06ACEFF6FEA501FFFFFFFF"
        },
        { ADDR_TYPE_ETH,
          "0xAA",
          "AA00000000000000000000000000000000000000",
          "AAFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        },
        /* TRX prefix "T" (addrtype=65=0x41): range must cover entire addrtype
         * space, with high = 0x41FF...FF (not 0x4200...00) */
        { 65,
          "T",
          "41000000000000000000000000000000000000000000000000",
          "41FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        },
        /* XDAG has no version byte: 24-byte numbers [hash160][checksum].
         * "1" means a leading zero byte: [0, 2^184 - 1] */
        { ADDR_TYPE_XDAG,
          "1",
          "0",
          "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        },
        /* "4": the 32-char range lies below 2^184 (it would start with "1"),
         * only the 33-char range [3*58^32, 4*58^32 - 1] remains */
        { ADDR_TYPE_XDAG,
          "4",
          "20E8609A18D1B8D6E0A2B358950A0367F27DF78300000000",
          "2BE080CD766CF673D62E44761C0D59DFEDFD4A03FFFFFFFF"
        },
        /* "R" only occurs in 32-char addresses: [24*58^31, 25*58^31 - 1] */
        { ADDR_TYPE_XDAG,
          "R",
          "0489FBAB52DF22529A9207150BBAC2AD3BEE107C00000000",
          "04BA6627CBA86E6B6102C76096E28AC9C917FBD67FFFFFFF"
        },
    };

    size_t n = sizeof(tests) / sizeof(tests[0]);

    for (int i = 0; i < n; i++) {
        char *got;
        BIGNUM *ranges[4];
        BN_CTX *bnctx = BN_CTX_new();

        int rv = get_prefix_ranges(tests[i].addrtype, tests[i].pattern, ranges, bnctx);
        ck_assert_int_eq(0, rv);


        got = BN_bn2hex(ranges[0]);
        ck_assert_mem_eq(got, tests[i].result_0, strlen(tests[i].result_0));
        OPENSSL_free(got);

        got = BN_bn2hex(ranges[1]);
        ck_assert_mem_eq(got, tests[i].result_1, strlen(tests[i].result_1));
        OPENSSL_free(got);
    }
}
END_TEST

START_TEST(test_eth_suffix_parsing)
{
    /* Test suffix-only pattern: *dead */
    {
        vg_context_t *vcp = vg_prefix_context_new(ADDR_TYPE_ETH, PRIV_TYPE_ETH, 0);
        ck_assert_ptr_nonnull(vcp);
        const char *patterns[] = { "*dead" };
        int rv = vg_context_add_patterns(vcp, patterns, 1);
        ck_assert_int_eq(1, rv);

        vg_prefix_context_t *vcpp = (vg_prefix_context_t *)vcp;
        ck_assert_int_eq(1, vcpp->vcp_has_suffix);
        ck_assert_int_eq(4, vcpp->vcp_suffix_len);
        /* mask should have last 2 bytes set: ...0000FFFF */
        ck_assert_int_eq(0x00, vcpp->vcp_suffix_mask[17]);
        ck_assert_int_eq(0xFF, vcpp->vcp_suffix_mask[18]);
        ck_assert_int_eq(0xFF, vcpp->vcp_suffix_mask[19]);
        /* target should be ...0000DEAD */
        ck_assert_int_eq(0xDE, vcpp->vcp_suffix_target[18]);
        ck_assert_int_eq(0xAD, vcpp->vcp_suffix_target[19]);
        ck_assert_int_eq(0x00, vcpp->vcp_suffix_target[17]);

        vg_context_free(vcp);
    }

    /* Test odd-length suffix: *abc (3 hex chars = 12 bits) */
    {
        vg_context_t *vcp = vg_prefix_context_new(ADDR_TYPE_ETH, PRIV_TYPE_ETH, 0);
        const char *patterns[] = { "*abc" };
        int rv = vg_context_add_patterns(vcp, patterns, 1);
        ck_assert_int_eq(1, rv);

        vg_prefix_context_t *vcpp = (vg_prefix_context_t *)vcp;
        ck_assert_int_eq(1, vcpp->vcp_has_suffix);
        ck_assert_int_eq(3, vcpp->vcp_suffix_len);
        /* mask: last 12 bits = ...00000FFF */
        ck_assert_int_eq(0x0F, vcpp->vcp_suffix_mask[18]);
        ck_assert_int_eq(0xFF, vcpp->vcp_suffix_mask[19]);
        ck_assert_int_eq(0x00, vcpp->vcp_suffix_mask[17]);
        /* target: ...00000ABC */
        ck_assert_int_eq(0x0A, vcpp->vcp_suffix_target[18]);
        ck_assert_int_eq(0xBC, vcpp->vcp_suffix_target[19]);

        vg_context_free(vcp);
    }

    /* Test combined prefix+suffix: 0xAA*beef */
    {
        vg_context_t *vcp = vg_prefix_context_new(ADDR_TYPE_ETH, PRIV_TYPE_ETH, 0);
        const char *patterns[] = { "0xAA*beef" };
        int rv = vg_context_add_patterns(vcp, patterns, 1);
        ck_assert_int_eq(1, rv);

        vg_prefix_context_t *vcpp = (vg_prefix_context_t *)vcp;
        ck_assert_int_eq(1, vcpp->vcp_has_suffix);
        ck_assert_int_eq(4, vcpp->vcp_suffix_len);
        /* suffix target: ...0000BEEF */
        ck_assert_int_eq(0xBE, vcpp->vcp_suffix_target[18]);
        ck_assert_int_eq(0xEF, vcpp->vcp_suffix_target[19]);
        /* prefix should also be added (npatterns > 0 indicates prefix was registered) */
        ck_assert(!avl_root_empty(&vcpp->vcp_avlroot));

        vg_context_free(vcp);
    }
}
END_TEST

START_TEST(test_eth_suffix_match_verify)
{
    /* Test binary suffix match verification */
    {
        vg_context_t *vcp = vg_prefix_context_new(ADDR_TYPE_ETH, PRIV_TYPE_ETH, 1); /* case-insensitive */
        const char *patterns[] = { "*dead" };
        vg_context_add_patterns(vcp, patterns, 1);
        vg_prefix_context_t *vcpp = (vg_prefix_context_t *)vcp;

        /* Address ending with ...dead should match */
        unsigned char addr_match[20] = {0};
        addr_match[18] = 0xDE;
        addr_match[19] = 0xAD;
        ck_assert_int_eq(1, vg_prefix_check_suffix(vcpp, addr_match));

        /* Address ending with ...beef should not match */
        unsigned char addr_no[20] = {0};
        addr_no[18] = 0xBE;
        addr_no[19] = 0xEF;
        ck_assert_int_eq(0, vg_prefix_check_suffix(vcpp, addr_no));

        /* Any prefix bytes should not affect suffix match */
        unsigned char addr_prefix[20];
        memset(addr_prefix, 0xFF, 20);
        addr_prefix[18] = 0xDE;
        addr_prefix[19] = 0xAD;
        ck_assert_int_eq(1, vg_prefix_check_suffix(vcpp, addr_prefix));

        vg_context_free(vcp);
    }
}
END_TEST

START_TEST(test_trx_suffix_parsing)
{
    /* Test suffix-only pattern: *xyz */
    {
        TRXFlag = 1;
        vg_context_t *vcp = vg_prefix_context_new(65, 193, 0);
        ck_assert_ptr_nonnull(vcp);
        const char *patterns[] = { "*xyz" };
        int rv = vg_context_add_patterns(vcp, patterns, 1);
        ck_assert_int_eq(1, rv);

        vg_prefix_context_t *vcpp = (vg_prefix_context_t *)vcp;
        ck_assert_int_eq(1, vcpp->vcp_has_suffix);
        ck_assert_int_eq(3, vcpp->vcp_suffix_len);

        /* divisor = 58^3 = 195112 */
        ck_assert(vcpp->vcp_suffix_divisor == 195112ULL);

        /* target = x*58^2 + y*58 + z
         * In Base58 alphabet "123456789ABCDEFGH JKLMN PQRSTUVWXYZ abcdefghijk mnopqrstuvwxyz":
         * x=55, y=56, z=57
         * target = 55*3364 + 56*58 + 57 = 185020 + 3248 + 57 = 188325 */
        ck_assert(vcpp->vcp_suffix_b58target == 188325ULL);

        /* AVL tree should be empty (suffix-only) */
        ck_assert(avl_root_empty(&vcpp->vcp_avlroot));

        vg_context_free(vcp);
        TRXFlag = 0;
    }

    /* Test combined prefix+suffix: TJ*abc */
    {
        TRXFlag = 1;
        vg_context_t *vcp = vg_prefix_context_new(65, 193, 0);
        const char *patterns[] = { "TJ*abc" };
        int rv = vg_context_add_patterns(vcp, patterns, 1);
        ck_assert_int_eq(1, rv);

        vg_prefix_context_t *vcpp = (vg_prefix_context_t *)vcp;
        ck_assert_int_eq(1, vcpp->vcp_has_suffix);
        ck_assert_int_eq(3, vcpp->vcp_suffix_len);
        ck_assert(vcpp->vcp_suffix_divisor == 195112ULL);

        /* a=33, b=34, c=35 in Base58
         * target = 33*3364 + 34*58 + 35 = 111012 + 1972 + 35 = 113019 */
        ck_assert(vcpp->vcp_suffix_b58target == 113019ULL);

        /* Prefix should be registered in AVL tree */
        ck_assert(!avl_root_empty(&vcpp->vcp_avlroot));

        vg_context_free(vcp);
        TRXFlag = 0;
    }

    /* Test invalid Base58 character in suffix */
    {
        TRXFlag = 1;
        vg_context_t *vcp = vg_prefix_context_new(65, 193, 0);
        const char *patterns[] = { "*0OI" }; /* 0, O, I are not valid Base58 */
        int rv = vg_context_add_patterns(vcp, patterns, 1);
        ck_assert_int_eq(0, rv); /* Should fail */

        vg_context_free(vcp);
        TRXFlag = 0;
    }
}
END_TEST

START_TEST(test_trx_suffix_cpu_verify)
{
    /* Test CPU-side TRX suffix verification using a known address.
     *
     * Use a known TRX address: binres = [0x41][20-byte hash]
     * We compute the Base58Check address, take its suffix, and verify
     * that vg_prefix_check_suffix_trx matches correctly.
     */
    {
        TRXFlag = 1;

        /* Known: address "TNYpSezj43FNgFKQxenHRXbfi3j2qqfMnc"
         * version = 0x41 = 65
         * hash = a3e53e209f76e7de1e0b1eef9b1c5c9d0a2e2cf0 (example) */
        unsigned char binres[21];
        binres[0] = 0x41;
        /* Use all zeros for hash - this gives a deterministic address */
        memset(binres + 1, 0, 20);

        /* Compute the expected address */
        char addr_buf[64];
        vg_b58_encode_check(binres, 21, addr_buf);
        size_t addr_len = strlen(addr_buf);

        /* Use the last 3 chars as suffix */
        ck_assert(addr_len >= 3);
        char suffix[4];
        memcpy(suffix, addr_buf + (addr_len - 3), 3);
        suffix[3] = '\0';

        /* Build a pattern with this suffix */
        char pattern[16];
        snprintf(pattern, sizeof(pattern), "*%s", suffix);

        vg_context_t *vcp = vg_prefix_context_new(65, 193, 0);
        const char *patterns[] = { pattern };
        int rv = vg_context_add_patterns(vcp, patterns, 1);
        ck_assert_int_eq(1, rv);

        vg_prefix_context_t *vcpp = (vg_prefix_context_t *)vcp;
        /* Should match */
        ck_assert_int_eq(1, vg_prefix_check_suffix_trx(vcpp, binres));

        /* Different hash should likely not match */
        unsigned char binres2[21];
        binres2[0] = 0x41;
        memset(binres2 + 1, 0xFF, 20);
        /* This may or may not match by coincidence, so just verify
         * that the function runs without crashing. For a rigorous
         * test, we check the actual address suffix. */
        char addr_buf2[64];
        vg_b58_encode_check(binres2, 21, addr_buf2);
        size_t addr_len2 = strlen(addr_buf2);
        int should_match = (addr_len2 >= 3 &&
                           memcmp(addr_buf2 + (addr_len2 - 3), suffix, 3) == 0);
        ck_assert_int_eq(should_match,
                        vg_prefix_check_suffix_trx(vcpp, binres2));

        vg_context_free(vcp);
        TRXFlag = 0;
    }
}
END_TEST

START_TEST(test_xdag)
{
    /* Key from the xdagj CLI wallet docs ("--importprivatekey" example),
     * its hash160 there is f72a663cacd5fc5eed48633d8cb509781ef29e76 */
    const char *privhex = "8f30bc86f42f55d8d64dd26a5428fc1e65f0616823153c084b43aad76cd97e04";
    const char *address = "PXthLotQpywwDB9ksCQYCJdwPKxKGxZKX";
    char buf[128];

    /* Address and private key encoding */
    {
        EC_KEY *pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
        BIGNUM *bn = NULL;
        BN_hex2bn(&bn, privhex);
        ck_assert_int_eq(1, vg_set_privkey(bn, pkey));

        vg_encode_address(EC_KEY_get0_public_key(pkey), EC_KEY_get0_group(pkey),
                          ADDR_TYPE_XDAG, VCF_PUBKEY, buf);
        ck_assert_str_eq(address, buf);
        vg_encode_address_compressed(EC_KEY_get0_public_key(pkey), EC_KEY_get0_group(pkey),
                                     ADDR_TYPE_XDAG, buf);
        ck_assert_str_eq(address, buf);
        vg_encode_privkey(pkey, PRIV_TYPE_XDAG, buf);
        ck_assert_str_eq(privhex, buf);
        vg_encode_privkey_compressed(pkey, PRIV_TYPE_XDAG, buf);
        ck_assert_str_eq(privhex, buf);

        /* Leading zero bytes are kept */
        BN_set_word(bn, 1);
        vg_set_privkey(bn, pkey);
        vg_encode_privkey_hex(pkey, buf);
        ck_assert_str_eq("0000000000000000000000000000000000000000000000000000000000000001", buf);

        BN_free(bn);
        EC_KEY_free(pkey);
    }

    /* "Q" also covers the top of the 33-char addresses, clipped at 2^192 - 1 */
    {
        BIGNUM *ranges[4];
        BN_CTX *bnctx = BN_CTX_new();
        char *got;

        ck_assert_int_eq(0, get_prefix_ranges(ADDR_TYPE_XDAG, "Q", ranges, bnctx));
        ck_assert_ptr_nonnull(ranges[2]);
        got = BN_bn2hex(ranges[3]);
        ck_assert_str_eq("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", got);
        OPENSSL_free(got);
        free_ranges(ranges);

        /* Longer than the 33-char address */
        ck_assert_int_eq(-2, get_prefix_ranges(ADDR_TYPE_XDAG,
                         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ranges, bnctx));
        BN_CTX_free(bnctx);
    }

    /* Base58 suffix: parsing and CPU verification */
    {
        vg_context_t *vcp = vg_prefix_context_new(ADDR_TYPE_XDAG, PRIV_TYPE_XDAG, 0);
        const char *patterns[] = { "PXth*GxZKX" };
        unsigned char binres[28] = {0}; /* [unused][hash160][checksum] */

        ck_assert_int_eq(1, vg_context_add_patterns(vcp, patterns, 1));
        vg_prefix_context_t *vcpp = (vg_prefix_context_t *)vcp;
        ck_assert_int_eq(1, vcpp->vcp_has_suffix);
        ck_assert(vcpp->vcp_suffix_divisor == 656356768ULL);   /* 58^5 */
        ck_assert(vcpp->vcp_suffix_b58target == 180587322ULL); /* "GxZKX" */
        ck_assert(!avl_root_empty(&vcpp->vcp_avlroot));

        memcpy(binres + 1, from_hex("f72a663cacd5fc5eed48633d8cb509781ef29e76"), 20);
        ck_assert_int_eq(1, vg_prefix_check_suffix_xdag(vcpp, binres));
        binres[20] ^= 1;
        ck_assert_int_eq(0, vg_prefix_check_suffix_xdag(vcpp, binres));

        vg_context_free(vcp);
    }
}
END_TEST
