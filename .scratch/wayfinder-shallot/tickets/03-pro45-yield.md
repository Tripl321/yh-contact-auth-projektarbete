# 03 — test_pro45: vilken sida viker sig

## Question

Testerna kräver STM32-register (`STM32_RNG_BASE`/`RNG_CR`) som firmwaren
avsiktligt inte har (Zephyr `sys_csrand_get`, GTZC-skäl dokumenterat):
uppdateras testerna till beslutad design, eller kräver specen registret
tillbaka?

## Typ

grilling (HITL): beslut + eventuell testuppdatering.
