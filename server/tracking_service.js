/**
 * 5-Why Tracking System
 * Suivi des incidents avec rappels automatiques jusqu'à résolution
 */

const fs = require('fs');
const path = require('path');

class TrackingService {
    constructor() {
        this.dataPath = path.join(__dirname, 'data');
        this.techniciansFile = path.join(this.dataPath, 'technicians.json');
        this.incidentsFile = path.join(this.dataPath, 'incidents.json');
        
        this.ensureDataFolder();
        this.loadData();
        
        console.log('[TRACKING] Service initialized');
    }

    ensureDataFolder() {
        if (!fs.existsSync(this.dataPath)) {
            fs.mkdirSync(this.dataPath, { recursive: true });
        }
    }

    loadData() {
        // Charger les techniciens
        if (fs.existsSync(this.techniciansFile)) {
            this.technicians = JSON.parse(fs.readFileSync(this.techniciansFile, 'utf8'));
        } else {
            this.technicians = [];
            this.saveTechnicians();
        }

        // Charger les incidents
        if (fs.existsSync(this.incidentsFile)) {
            this.incidents = JSON.parse(fs.readFileSync(this.incidentsFile, 'utf8'));
        } else {
            this.incidents = [];
            this.saveIncidents();
        }
    }

    saveTechnicians() {
        fs.writeFileSync(this.techniciansFile, JSON.stringify(this.technicians, null, 2));
    }

    saveIncidents() {
        fs.writeFileSync(this.incidentsFile, JSON.stringify(this.incidents, null, 2));
    }

    // ============================================
    // GESTION DES TECHNICIENS
    // ============================================

    /**
     * Ajouter un nouveau technicien
     */
    addTechnician(technicianData) {
        const technician = {
            id: `TECH-${Date.now()}`,
            name: technicianData.name,
            email: technicianData.email,
            role: technicianData.role, // 'mecano' | 'electro' | 'supervisor'
            shift: technicianData.shift || 'day', // 'day' | 'evening' | 'night'
            department: technicianData.department || 'packaging',
            createdAt: new Date().toISOString(),
            active: true
        };

        this.technicians.push(technician);
        this.saveTechnicians();
        console.log(`[TRACKING] Technician added: ${technician.name} (${technician.role})`);
        return technician;
    }

    /**
     * Obtenir tous les techniciens
     */
    getTechnicians(filter = {}) {
        let result = this.technicians.filter(t => t.active);
        
        if (filter.role) {
            result = result.filter(t => t.role === filter.role);
        }
        if (filter.shift) {
            result = result.filter(t => t.shift === filter.shift);
        }
        
        return result;
    }

    /**
     * Mettre à jour un technicien
     */
    updateTechnician(id, updates) {
        const index = this.technicians.findIndex(t => t.id === id);
        if (index !== -1) {
            this.technicians[index] = { ...this.technicians[index], ...updates };
            this.saveTechnicians();
            return this.technicians[index];
        }
        return null;
    }

    /**
     * Désactiver un technicien
     */
    deactivateTechnician(id) {
        return this.updateTechnician(id, { active: false });
    }

    // ============================================
    // GESTION DES INCIDENTS 5-WHY
    // ============================================

    /**
     * Créer un nouvel incident à suivre
     */
    createIncident(incidentData) {
        const incident = {
            id: `INC-${Date.now()}`,
            title: incidentData.title,
            description: incidentData.description,
            component: incidentData.component, // 'Star Wheel', 'Lug Chain', etc.
            line: incidentData.line || 'Ligne 1',
            
            // Rapport 5-Why
            report: incidentData.report || null,
            rootCause: incidentData.rootCause || null,
            
            // Assignation
            assignedTo: incidentData.assignedTo || [], // IDs des techniciens
            supervisor: incidentData.supervisor || null,
            
            // Statuts
            status: 'open', // 'open' | 'in_progress' | 'pending_verification' | 'resolved' | 'closed'
            priority: incidentData.priority || 'medium', // 'low' | 'medium' | 'high' | 'critical'
            
            // Actions
            correctiveAction: incidentData.correctiveAction || null,
            preventiveAction: incidentData.preventiveAction || null,
            correctiveCompleted: false,
            preventiveCompleted: false,
            
            // Dates
            createdAt: new Date().toISOString(),
            dueDate: incidentData.dueDate || this.calculateDueDate(incidentData.priority),
            resolvedAt: null,
            closedAt: null,
            
            // Rappels
            remindersSent: 0,
            lastReminderAt: null,
            nextReminderAt: this.calculateNextReminder(),
            
            // Historique
            history: [{
                action: 'created',
                timestamp: new Date().toISOString(),
                by: incidentData.createdBy || 'system'
            }]
        };

        this.incidents.push(incident);
        this.saveIncidents();
        console.log(`[TRACKING] Incident created: ${incident.id} - ${incident.title}`);
        return incident;
    }

    calculateDueDate(priority) {
        const days = {
            critical: 1,
            high: 3,
            medium: 7,
            low: 14
        };
        const dueDate = new Date();
        dueDate.setDate(dueDate.getDate() + (days[priority] || 7));
        return dueDate.toISOString();
    }

    calculateNextReminder() {
        const nextReminder = new Date();
        nextReminder.setDate(nextReminder.getDate() + 1); // Rappel dans 24h
        return nextReminder.toISOString();
    }

    /**
     * Mettre à jour le statut d'un incident
     */
    updateIncidentStatus(id, status, updatedBy = 'system', notes = '') {
        const incident = this.incidents.find(i => i.id === id);
        if (!incident) return null;

        const oldStatus = incident.status;
        incident.status = status;
        
        incident.history.push({
            action: 'status_changed',
            from: oldStatus,
            to: status,
            timestamp: new Date().toISOString(),
            by: updatedBy,
            notes
        });

        if (status === 'resolved') {
            incident.resolvedAt = new Date().toISOString();
        }
        if (status === 'closed') {
            incident.closedAt = new Date().toISOString();
        }

        this.saveIncidents();
        console.log(`[TRACKING] Incident ${id} status: ${oldStatus} → ${status}`);
        return incident;
    }

    /**
     * Marquer une action comme complétée
     */
    completeAction(id, actionType, completedBy, notes = '') {
        const incident = this.incidents.find(i => i.id === id);
        if (!incident) return null;

        if (actionType === 'corrective') {
            incident.correctiveCompleted = true;
        } else if (actionType === 'preventive') {
            incident.preventiveCompleted = true;
        }

        incident.history.push({
            action: `${actionType}_completed`,
            timestamp: new Date().toISOString(),
            by: completedBy,
            notes
        });

        // Si les deux actions sont complétées, passer en pending_verification
        if (incident.correctiveCompleted && incident.preventiveCompleted) {
            this.updateIncidentStatus(id, 'pending_verification', completedBy, 'All actions completed');
        }

        this.saveIncidents();
        return incident;
    }

    /**
     * Assigner des techniciens à un incident
     */
    assignTechnicians(incidentId, technicianIds, assignedBy = 'system') {
        const incident = this.incidents.find(i => i.id === incidentId);
        if (!incident) return null;

        incident.assignedTo = technicianIds;
        incident.history.push({
            action: 'assigned',
            technicians: technicianIds,
            timestamp: new Date().toISOString(),
            by: assignedBy
        });

        this.saveIncidents();
        return incident;
    }

    /**
     * Obtenir les incidents en cours
     */
    getOpenIncidents() {
        return this.incidents.filter(i => 
            !['resolved', 'closed'].includes(i.status)
        ).sort((a, b) => {
            const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
            return priorityOrder[a.priority] - priorityOrder[b.priority];
        });
    }

    /**
     * Obtenir les incidents nécessitant un rappel
     */
    getIncidentsNeedingReminder() {
        const now = new Date();
        return this.incidents.filter(i => {
            if (['resolved', 'closed'].includes(i.status)) return false;
            if (!i.nextReminderAt) return false;
            return new Date(i.nextReminderAt) <= now;
        });
    }

    /**
     * Marquer un rappel comme envoyé
     */
    markReminderSent(id) {
        const incident = this.incidents.find(i => i.id === id);
        if (!incident) return null;

        incident.remindersSent++;
        incident.lastReminderAt = new Date().toISOString();
        
        // Prochain rappel dans 24-48h selon priorité
        const hours = incident.priority === 'critical' ? 24 : 48;
        const nextReminder = new Date();
        nextReminder.setHours(nextReminder.getHours() + hours);
        incident.nextReminderAt = nextReminder.toISOString();

        incident.history.push({
            action: 'reminder_sent',
            count: incident.remindersSent,
            timestamp: new Date().toISOString()
        });

        this.saveIncidents();
        return incident;
    }

    /**
     * Obtenir le dashboard de suivi
     */
    getDashboard() {
        const all = this.incidents;
        const open = all.filter(i => i.status === 'open');
        const inProgress = all.filter(i => i.status === 'in_progress');
        const pendingVerification = all.filter(i => i.status === 'pending_verification');
        const resolved = all.filter(i => i.status === 'resolved');
        const closed = all.filter(i => i.status === 'closed');
        
        const overdue = all.filter(i => {
            if (['resolved', 'closed'].includes(i.status)) return false;
            return new Date(i.dueDate) < new Date();
        });

        return {
            total: all.length,
            byStatus: {
                open: open.length,
                in_progress: inProgress.length,
                pending_verification: pendingVerification.length,
                resolved: resolved.length,
                closed: closed.length
            },
            overdue: overdue.length,
            overdueIncidents: overdue,
            needingReminder: this.getIncidentsNeedingReminder().length,
            techniciansCount: this.technicians.filter(t => t.active).length,
            recentIncidents: this.getOpenIncidents().slice(0, 10)
        };
    }

    /**
     * Obtenir l'historique d'un incident
     */
    getIncidentHistory(id) {
        const incident = this.incidents.find(i => i.id === id);
        if (!incident) return null;
        return incident.history;
    }

    /**
     * Rechercher des incidents
     */
    searchIncidents(query) {
        const q = query.toLowerCase();
        return this.incidents.filter(i => 
            i.title.toLowerCase().includes(q) ||
            i.description?.toLowerCase().includes(q) ||
            i.component?.toLowerCase().includes(q) ||
            i.rootCause?.toLowerCase().includes(q)
        );
    }
}

module.exports = TrackingService;
