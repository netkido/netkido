# Política de seguridad / Security policy

## Avisar de una vulnerabilidad

No abras una incidencia pública. Usa **«Report a vulnerability»** en la pestaña *Security* de este
repositorio (aviso privado de GitHub). Incluye la versión afectada, cómo reproducirlo y su impacto.

Respondemos en un plazo de 3 días laborables, te mantenemos al tanto de la corrección y, si lo
deseas, te reconocemos en las notas de la versión que lo corrige.

*Please do not open public issues for security problems: use "Report a vulnerability" in this
repository's Security tab. We reply within 3 business days.*

## Versiones con soporte

Solo la última versión publicada recibe correcciones de seguridad.

## Alcance

El servidor (`server/`), el hub (`hub/netkido-hub-apply`), el agente y el instalador de sedes
(`node/`). Interesa especialmente: saltarse la firma de la API de los agentes, que una sede
anuncie o reciba tráfico que no le corresponde, y ejecución de código en el servidor o en las sedes.
