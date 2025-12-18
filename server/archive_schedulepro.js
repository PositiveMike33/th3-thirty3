const GoogleService = require('./google_service');
const IDENTITY = require('./config/identity');

async function archiveSchedulePro() {
    const googleService = new GoogleService();
    const accounts = IDENTITY.accounts;

    console.log("===== ARCHIVAGE SCHEDULEPRO =====");

    for (const email of accounts) {
        console.log(`\n[COMPTE] ${email}`);
        const auth = await googleService.getClient(email);
        if (!auth) {
            console.log("  -> Non connecté. Ignoré.");
            continue;
        }

        const { google } = require('googleapis');
        const gmail = google.gmail({ version: 'v1', auth });

        try {
            // Find all SchedulePro emails (unread or read) in INBOX
            let pageToken = null;
            let totalArchived = 0;

            do {
                const res = await gmail.users.messages.list({
                    userId: 'me',
                    q: 'label:INBOX (from:SchedulePro OR subject:"SPRO")',
                    maxResults: 50,
                    pageToken: pageToken
                });

                const messages = res.data.messages;
                if (!messages || messages.length === 0) {
                    if (totalArchived === 0) console.log("  -> Aucun email trouvé dans la boîte de réception.");
                    break;
                }

                console.log(`  -> Trouvé ${messages.length} emails à archiver...`);

                for (const msg of messages) {
                    const success = await googleService.archiveEmail(email, msg.id);
                    if (success) {
                        process.stdout.write(".");
                        totalArchived++;
                    } else {
                        process.stdout.write("X");
                    }
                }
                pageToken = res.data.nextPageToken;
            } while (pageToken);

            console.log(`\n  -> Total archivé : ${totalArchived}`);

        } catch (error) {
            console.error(`  -> Erreur: ${error.message}`);
        }
    }
    console.log("\n===== TERMINÉ =====");
}

archiveSchedulePro();
