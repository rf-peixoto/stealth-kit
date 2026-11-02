#include <stdio.h>
#include <string.h>

/* file-scope: MUST be left alone (static initializer needs a constant) */
static const char *banner = "FILE_SCOPE_BANNER_SECRET";
const char version_tag[] = "VERSION_1_2_3_SECRET";

#define GREETING "MACRO_GREETING_SECRET"   /* in a macro -> left alone */

struct cfg { const char *name; int v; };
/* file-scope aggregate initializer -> left alone */
static struct cfg table[] = {
    { "TABLE_ENTRY_SECRET", 1 },
    { "ANOTHER_ENTRY_SECRET", 2 },
};

static void helper(void) {
    /* local array init from a literal -> MUST be left alone (char[] copy) */
    char local_arr[] = "LOCAL_ARRAY_SECRET";
    /* local static -> MUST be left alone */
    static const char *slocal = "LOCAL_STATIC_SECRET";
    /* sizeof operand -> MUST be left alone (size would change) */
    size_t sz = sizeof("SIZEOF_OPERAND_SECRET");
    printf("%s %s %zu\n", local_arr, slocal, sz);
}

int main(void) {
    /* these are all SAFE: plain call arguments / pointer init / return paths */
    printf("HELLO_OBFUSCATE_ME\n");
    const char *msg = "POINTER_INIT_OBFUSCATE_ME";
    printf("%s\n", msg);
    puts("PUTS_ARG_OBFUSCATE_ME");

    /* adjacent concatenation -> treated as one unit */
    printf("%s\n", "CONCAT_PART_ONE_" "CONCAT_PART_TWO_OBFUSCATE");

    /* escapes incl. quote and hex */
    printf("%s\n", "ESCAPES_\t_TAB_\"_QUOTE_\x41_OBFUSCATE");

    /* opt-out marker keeps this one readable */
    printf("%s\n", "KEEP_ME_READABLE_SECRET" /*noobf*/);

    if (strcmp(msg, "POINTER_INIT_OBFUSCATE_ME") == 0)
        printf("%s\n", "COMPARE_MATCHED_OBFUSCATE");

    helper();
    (void)banner; (void)version_tag; (void)table;
    return 0;
}
