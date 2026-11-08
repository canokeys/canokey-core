// SPDX-License-Identifier: Apache-2.0
// Included after pinned test_apdu.c; only source callbacks are test adapters.
enum { PARSER_MAX_REQUEST_BYTES = 1296 }; // Pinned CIU ABI, checked at startup.
typedef struct {
  uint8_t bytes[PARSER_MAX_REQUEST_BYTES + 3];
  size_t length, reads, trigger, failures, largest;
  unsigned mode;
  bool cancelled;
} parser_input_t;

static int parser_source_read(void *ctx, size_t offset, uint8_t *out, size_t length) {
  parser_input_t *input = ctx;
  assert_true(offset >= 3 && offset <= input->length + 3);
  assert_true(length <= input->length + 3 - offset);
  ++input->reads;
  if (length > input->largest) input->largest = length;
  if (input->reads == input->trigger) {
    if (input->mode == 2 || input->mode == 3) input->cancelled = true;
    if (input->mode == 1 || input->mode == 2) {
      ++input->failures;
      return -1;
    }
  }
  memcpy(out, input->bytes + offset, length);
  return 0;
}

static int parser_source_cancelled(void *ctx) { return ((parser_input_t *)ctx)->cancelled; }

static void portable_parser_loop(void) {
  assert_int_equal(CTAP_MAX_REQUEST_SIZE, PARSER_MAX_REQUEST_BYTES);
  // Executes the release's real parser and emitted minPinLength assertions,
  // for both memory and source parsing with colliding stored RP representations.
  test_make_credential_min_pin_exact_rpid(NULL);
  puts("RP_EXACT cases=4 passed");
  char line[PARSER_MAX_REQUEST_BYTES * 2 + 128], hex[PARSER_MAX_REQUEST_BYTES * 2 + 1];
  while (fgets(line, sizeof(line), stdin)) {
    parser_input_t input = {0};
    unsigned command;
    assert_int_equal(sscanf(line, "%u %u %zu %2592s", &command, &input.mode, &input.trigger, hex), 4);
    const size_t digits = strlen(hex);
    assert_true(digits % 2 == 0 && digits / 2 <= CTAP_MAX_REQUEST_SIZE);
    input.length = digits / 2;
    input.cancelled = input.mode == 4;
    for (size_t i = 0; i < input.length; ++i) {
      unsigned byte;
      assert_int_equal(sscanf(hex + i * 2, "%2x", &byte), 1);
      input.bytes[3 + i] = (uint8_t)byte;
    }
    const ctap_req_src_t source = {.read = parser_source_read, .cancelled = parser_source_cancelled,
                                  .ctx = &input, .base_offset = 3, .len = input.length};
    CborParser parser;
    union {
      CTAP_make_credential mc;
      CTAP_get_assertion ga;
      CTAP_client_pin pin;
      CTAP_credential_management cm;
      CTAP_config config;
      CTAP_large_blobs blob;
    } fields;
    uint8_t result;
#define PARSE(name, member)                                                                                            \
  (input.mode == 5 ? parse_##name(&parser, &fields.member, input.bytes + 3, input.length)                                \
                   : parse_##name##_src(&parser, &fields.member, &source, input.length))
    switch (command) {
    case CTAP_MAKE_CREDENTIAL: result = PARSE(make_credential, mc); break;
    case CTAP_GET_ASSERTION: result = PARSE(get_assertion, ga); break;
    case CTAP_CLIENT_PIN: result = PARSE(client_pin, pin); break;
    case CTAP_CREDENTIAL_MANAGEMENT: result = PARSE(credential_management, cm); break;
    case CTAP_CONFIG: result = PARSE(config, config); break;
    case CTAP_LARGE_BLOBS: result = PARSE(large_blobs, blob); break;
    default: assert_true(false); return;
    }
#undef PARSE
    printf("RESULT %u %zu %zu %u %zu\n", result, input.reads, input.failures, input.cancelled, input.largest);
  }
}
