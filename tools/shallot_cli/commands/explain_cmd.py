"""`shallot explain` — lokal förklaring av SHALLOT-begrepp (PRO-100).

Utan flaggor skrivs kuraterad lokal text (offline, alltid tillgänglig).
Med `--ai` utvecklar en lokal Ollama-modell ämnet — endast loopback,
prompten innehåller enbart den lokala texten, aldrig hemligheter.
Saknas Ollama/modell: tydligt fel på stderr, exit 2 (lokal text visas).
"""

from __future__ import annotations

import sys

from shallot_cli import explain, ollama


def run_list() -> int:
    for name in explain.topic_names():
        print("%-12s %s" % (name, explain.TOPICS[name][0]))
    return 0


def run(topic: str, ai: bool = False, model: str = ollama.DEFAULT_MODEL,
        host: str | None = None) -> int:
    if topic not in explain.TOPICS:
        print("okänt ämne: %r (välj: %s)" % (topic, "|".join(explain.topic_names())),
              file=sys.stderr)
        return 2
    print(explain.render(topic))
    if not ai:
        return 0
    try:
        base = ollama.resolve_base(host)
    except ollama.OllamaError as e:
        print("AI-utveckling avbruten: %s" % e, file=sys.stderr)
        return 2
    try:
        if not ollama.model_available(base, model):
            print("AI-utveckling avbruten: modellen %r saknas lokalt — "
                  "hämta med `ollama pull %s`" % (model, model.split(":")[0]),
                  file=sys.stderr)
            return 2
        answer = ollama.generate(base, model, explain.build_prompt(topic))
    except ollama.OllamaError as e:
        print("AI-utveckling avbruten: %s" % e, file=sys.stderr)
        return 2
    print("\n--- AI-utveckling (lokal modell %s, ej auktoritativ) ---\n" % model)
    print(answer)
    return 0
