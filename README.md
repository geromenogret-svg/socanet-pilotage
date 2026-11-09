# socanet-pilotage — Planning & pointage Socanet Services

Application de planning, pointage et suivi des heures (Socanet Nettoyage).

- `server.js` : serveur Node.js ≥ 22 sans dépendance (base SQLite intégrée, sessions, droits par rôle, sauvegarde nocturne).
- `public/` : interface (gestion sur ordinateur, pointage sur téléphone).
- Aucune donnée personnelle dans ce dépôt : les salariés, contrats et heures sont chargés au premier démarrage depuis `seed.json`, fourni uniquement sur le serveur.

Variables : `PORT` (3000), `DATA_DIR`, `BACKUP_DIR`, `SETUP_TOKEN` (création du compte administrateur), `TZ=America/Martinique`.
