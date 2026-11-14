idf_component_register(
    SRCS
        src/command.c
        src/crypto.c
        src/eap.c
        src/link.c
        src/message.c
        src/pair.c
        src/pod.c
        src/response.c
        src/x25519.c
        src/o5.c
        src/platform_mbedtls.c
    INCLUDE_DIRS include
    PRIV_REQUIRES mbedtls log esp_hw_support
)
