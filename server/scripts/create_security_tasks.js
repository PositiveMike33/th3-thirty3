/**
 * Script de création des tâches DartAI basées sur l'analyse de sécurité hybride
 * Crée 10 tâches correspondant aux 10 recommandations
 */

const DartService = require('./dart_service');

const SECURITY_TASKS = [
    {
        title: "[HYBRID-SEC] Intégrer protocoles cyber aux procédures SSE",
        description: `## Objectif
Intégrer formellement les protocoles de cybersécurité aux procédures de sécurité santé et environnement existantes sur le terrain.

## Actions requises
- Auditer les procédures SSE actuelles
- Identifier les points d'intégration cyber
- Rédiger les protocoles hybrides
- Former les responsables SSE
- Valider avec les équipes terrain

## Critères de succès
- 100% des procédures SSE incluent un volet cyber
- Formation dispensée à tous les responsables
- Documentation validée par RSSI et HSE`,
        priority: "high",
        tags: ["security", "hybrid", "compliance", "SSE"]
    },
    {
        title: "[HYBRID-SEC] Planifier simulations de crise IT/OT",
        description: `## Objectif
Organiser des simulations de crise régulières qui forcent la collaboration entre les équipes IT et les opérateurs de machines.

## Actions requises
- Définir 3 scénarios cyber-cinétiques réalistes
- Identifier les participants IT et OT
- Planifier exercice trimestriel
- Préparer grille d'évaluation
- Documenter les retours d'expérience

## Critères de succès
- 1 simulation par trimestre minimum
- Participation de toutes les équipes
- Amélioration mesurable à chaque exercice`,
        priority: "high",
        tags: ["security", "simulation", "crisis", "IT-OT"]
    },
    {
        title: "[HYBRID-SEC] Définir autorité décisionnelle humain vs capteurs",
        description: `## Objectif
Définir clairement l'autorité décisionnelle de l'humain dans la boucle lorsque les données des capteurs contredisent l'observation visuelle.

## Actions requises
- Lister les situations de contradiction possibles
- Définir arbre de décision
- Créer carte de référence rapide
- Former les opérateurs
- Tester en conditions simulées

## Critères de succès
- Procédure claire en moins de 30 secondes
- 0 ambiguïté sur qui décide
- Documentation accessible sur poste`,
        priority: "critical",
        tags: ["security", "decision", "human-loop", "sensors"]
    },
    {
        title: "[HYBRID-SEC] Renforcer contrôles d'accès post Red Team",
        description: `## Objectif
Renforcer les contrôles d'accès physique basés sur les résultats des audits de l'équipe rouge pour empêcher les intrusions non techniques.

## Actions requises
- Analyser rapports Red Team récents
- Identifier les vulnérabilités d'accès physique
- Mettre à jour les contrôles d'accès
- Tester les nouvelles mesures
- Documenter les changements

## Critères de succès
- 100% des vulnérabilités identifiées corrigées
- Nouveau test Red Team validant les correctifs
- Budget sécurité physique ajusté`,
        priority: "high",
        tags: ["security", "physical", "red-team", "access-control"]
    },
    {
        title: "[HYBRID-SEC] Former cadres à manipulation psychologique",
        description: `## Objectif
Former les cadres à reconnaître les tentatives de manipulation psychologique qui visent à contourner les contrôles technologiques.

## Actions requises
- Développer module de formation 2h
- Inclure cas pratiques réels
- Créer quiz d'évaluation
- Planifier sessions pour tous les cadres
- Établir refresh annuel

## Critères de succès
- 100% des cadres formés sous 3 mois
- Score moyen > 80% au quiz
- Signalements de tentatives en hausse (indicateur positif)`,
        priority: "medium",
        tags: ["security", "training", "social-engineering", "management"]
    },
    {
        title: "[HYBRID-SEC] Établir canaux communication hors bande",
        description: `## Objectif
Établir des canaux de communication d'urgence hors bande pour la gestion de crise lorsque les réseaux numériques sont compromis.

## Actions requises
- Identifier technologies alternatives (radio, satellite, messagers)
- Acquérir équipements nécessaires
- Former personnel clé
- Tester régulièrement
- Intégrer aux plans de continuité

## Critères de succès
- Canal opérationnel en < 5 minutes
- Couverture de tous les sites critiques
- Test mensuel réussi`,
        priority: "critical",
        tags: ["security", "communication", "crisis", "backup"]
    },
    {
        title: "[HYBRID-SEC] Auditer interfaces homme-machine",
        description: `## Objectif
Auditer régulièrement les interfaces homme-machine pour s'assurer qu'elles présentent les anomalies de sécurité de manière intuitive.

## Actions requises
- Inventorier toutes les IHM critiques
- Définir critères d'ergonomie sécurité
- Auditer avec opérateurs réels
- Prioriser les améliorations
- Implémenter changements

## Critères de succès
- 100% des IHM auditées
- Temps de détection anomalie réduit de 50%
- Retours opérateurs positifs`,
        priority: "medium",
        tags: ["security", "UX", "HMI", "audit"]
    },
    {
        title: "[HYBRID-SEC] Créer lexique commun cyber/opérations",
        description: `## Objectif
Créer un lexique commun entre les ingénieurs en cybersécurité et les chefs d'équipe d'usine pour éviter les malentendus critiques.

## Actions requises
- Identifier termes problématiques
- Rédiger définitions communes
- Valider avec les deux parties
- Distribuer et afficher
- Intégrer aux formations

## Critères de succès
- Lexique de 50+ termes validé
- Disponible en format poche
- Utilisé dans toutes les procédures`,
        priority: "medium",
        tags: ["security", "communication", "terminology", "training"]
    },
    {
        title: "[HYBRID-SEC] Implémenter vérifications manuelles commandes critiques",
        description: `## Objectif
Mettre en place des mécanismes de vérification manuelle pour valider les commandes critiques envoyées aux systèmes industriels autonomes.

## Actions requises
- Identifier commandes critiques (arrêt, démarrage, paramètres)
- Concevoir workflow de double validation
- Implémenter dans systèmes SCADA
- Former opérateurs
- Tester en production contrôlée

## Critères de succès
- 100% des commandes critiques avec double validation
- Temps de validation < 30 secondes
- 0 commande non autorisée exécutée`,
        priority: "critical",
        tags: ["security", "SCADA", "validation", "industrial"]
    },
    {
        title: "[HYBRID-SEC] Développer indicateurs compromission physique",
        description: `## Objectif
Développer des indicateurs de compromission physique qui peuvent alerter le personnel au sol d'une cyberattaque en cours.

## Actions requises
- Définir signes physiques d'attaque cyber
- Créer fiches d'alerte visuelles
- Former personnel terrain
- Établir procédure de remontée
- Intégrer au système d'alerte global

## Critères de succès
- 10+ indicateurs physiques définis
- Personnel formé à les reconnaître
- Temps de détection terrain < temps détection IT`,
        priority: "high",
        tags: ["security", "IOC", "physical", "detection"]
    }
];

async function createDartTasks() {
    console.log('=== CRÉATION TÂCHES DARTAI ===\n');
    
    const dart = new DartService();
    
    // Vérifier l'authentification
    const authResult = await dart.authenticate();
    if (!authResult) {
        console.error('❌ Authentification DartAI échouée');
        return { success: false, created: 0 };
    }
    
    console.log('✅ DartAI authentifié\n');
    
    let created = 0;
    const results = [];
    
    for (const task of SECURITY_TASKS) {
        console.log(`📋 Création: ${task.title}`);
        
        try {
            const result = await dart.createTask(task.title, {
                description: task.description,
                priority: task.priority,
                tags: task.tags
            });
            
            if (result.success) {
                console.log(`   ✅ Créée (ID: ${result.task?.id || 'N/A'})`);
                created++;
                results.push({ ...task, success: true, taskId: result.task?.id });
            } else {
                console.log(`   ⚠️ Échec: ${result.error || 'Unknown error'}`);
                results.push({ ...task, success: false, error: result.error });
            }
        } catch (error) {
            console.log(`   ❌ Erreur: ${error.message}`);
            results.push({ ...task, success: false, error: error.message });
        }
        
        // Délai entre créations
        await new Promise(r => setTimeout(r, 500));
    }
    
    console.log(`\n=== RÉSUMÉ ===`);
    console.log(`✅ Tâches créées: ${created}/${SECURITY_TASKS.length}`);
    
    return { success: created > 0, created, total: SECURITY_TASKS.length, results };
}

// Export
module.exports = { createDartTasks, SECURITY_TASKS };

// Exécution directe
if (require.main === module) {
    createDartTasks()
        .then(result => {
            console.log('\nRésultat:', result);
            process.exit(result.success ? 0 : 1);
        })
        .catch(err => {
            console.error('Erreur:', err);
            process.exit(1);
        });
}
