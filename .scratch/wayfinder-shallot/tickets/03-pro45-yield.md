# 03 — test_pro45: vilken sida viker sig

## Question

Testerna kräver STM32-register (`STM32_RNG_BASE`/`RNG_CR`) som firmwaren
avsiktligt inte har (Zephyr `sys_csrand_get`, GTZC-skäl dokumenterat):
uppdateras testerna till beslutad design, eller kräver specen registret
tillbaka?

## Resolution

Beslut A: testerna viker sig. test_pro45-testerna uppdaterade till
beslutad Zephyr-design (sys_csrand_get + GTZC; registerkonstanter
förbjudna), mergad som PR #45 (squash). Freeze-guard worktree-fix
medföljde (falskt positiv på .kilo-worktree). Suite HELT grön (538
passed, 0 failed) för första gången sedan driften uppstod. CLOSED.
