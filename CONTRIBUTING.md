# Cómo contribuir

¡Gracias por ayudar a mejorar Netkido! / *Thanks for helping! Issues and pull requests in English are welcome too.*

## Antes de empezar

- **Fallos:** abre una incidencia con la plantilla «Fallo»: sistema, versión (`netkido --version`,
  `netkido-agent status`) y los logs (`journalctl -u netkido`, `journalctl -u netkido-agent`).
  Quita antes claves, secretos y direcciones públicas.
- **Mejoras grandes:** abre primero una incidencia para hablarlo; así no trabajas en algo que no
  encaje con el diseño.
- **Seguridad:** nunca en una incidencia pública. Sigue [SECURITY.md](SECURITY.md).

## Pull requests

1. Una rama por cambio, con pruebas cuando se pueda (`python3 -m unittest discover -s tests -v`).
2. Los scripts de shell tienen que pasar `shellcheck` y el Python, `python3 -m py_compile`.
   Las pruebas automáticas (GitHub Actions) lo comprueban en cada pull request.
3. Sin dependencias nuevas en el agente ni en el servidor: solo la biblioteca estándar de Python.
4. **Firma cada commit (DCO).** Al firmar declaras que tienes derecho a aportar ese código bajo la
   licencia del proyecto ([Developer Certificate of Origin](https://developercertificate.org/)):

   ```bash
   git commit -s -m "Descripción del cambio"
   ```

   Eso añade `Signed-off-by: Tu Nombre <tu@email>` al mensaje. Los pull requests con commits sin
   firmar no se pueden aceptar.

## Licencia de las contribuciones

Netkido se publica bajo la [AGPL-3.0](LICENSE) y tiene además una edición comercial. Al contribuir
aceptas que tu aportación se publique bajo la AGPL-3.0 y que los mantenedores puedan incluirla
también en la edición comercial de Netkido.
