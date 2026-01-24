# Analyse de l'Intégration Astrometry.net pour WorldWide Telescope (WWT)

## 1. Conclusion : Utile ou Pas ?
**OUI**, c'est extrêmement utile et complémentaire à WorldWide Telescope.

## 2. Pourquoi ? (La Valeur Ajoutée)
WorldWide Telescope (WWT) est un excellent visualiseur de l'univers, mais il affiche principalement des données cataloguées. **Astrometry.net** apporte la capacité inverse : il prend une image inconnue (prise par un utilisateur ou une source externe) et détermine *exactement* où elle se trouve dans le ciel ("Plate Solving").

En combinant les deux, vous permettez aux utilisateurs de :
1.  **Uploader leurs propres astrophotos.**
2.  **Identifier automatiquement** les étoiles et objets présents sur l'image (via Astrometry.net).
3.  **Superposer leur image sur la carte WWT** à l'endroit exact, créant une expérience immersive personnalisée.

## 3. Analyse Technique

### L'API Astrometry.net
Le texte fourni confirme que l'API est accessible et conçue pour l'automatisation.
- **Points Clés :**
    - **Upload d'images** via API JSON.
    - **Récupération des métadonnées** (coordonnées RA/Dec, orientation, échelle).
    - **Protection Anti-Bot :** Nécessite un header HTTP spécifique (`Referer: https://nova.astrometry.net/api/login`) et une clé API.
    - **Client Python disponible :** Utile si nous avons un backend Python (ce qui est le cas avec vos services HexStrike/AI, bien que le serveur principal soit Node.js. Une implémentation Node.js est triviale).

### Intégration dans Th3-Thirty3
Actuellement, `SpaceDashboard.jsx` ne contient que le composant `WWTMapComponent`.

**Proposition d'Architecture :**
1.  **Frontend (`SpaceDashboard.jsx`) :**
    - Ajouter un panneau latéral ou une modale "Upload Image".
    - Permettre à l'utilisateur de glisser-déposer une astrophoto.
2.  **Backend (Node.js) :**
    - Créer une route `/api/astrometry/upload` qui agit comme un proxy.
    - Le backend stocke la *Clé API* (ne jamais exposer côté client).
    - Le backend envoie l'image à Astrometry.net avec les bons headers (`Referer`).
    - Le backend "poll" (vérifie) le statut du job jusqu'à calibrage réussi.
3.  **Visualisation (WWT) :**
    - Une fois calibrée, Astrometry.net renvoie les infos WCS (World Coordinate System).
    - Le `WWTMapComponent` utilise ces coordonnées pour créer un "Image Layer" et le placer par-dessus le fond de ciel.

## 4. Pré-requis
Pour implémenter cela, nous aurons besoin de :
1.  **Compte Astrometry.net :** Vous devez vous inscrire (gratuit) pour obtenir une **Clé API**.
2.  **Temps de Développement :** Environ 1-2 sessions pour créer le flux complet (Upload -> API -> WWT Overlay).

## Recommandation
Je recommande d'ajouter cette fonctionnalité au `SpaceDashboard`. Elle transforme le module d'une simple "carte" en un véritable outil d'analyse astronomique pour l'utilisateur.

---
**Voulez-vous que je commence à planifier cette implémentation (création des routes backend et UI d'upload) ?**
