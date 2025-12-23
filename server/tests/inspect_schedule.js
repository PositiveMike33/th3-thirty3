const GoogleService = require('./google_service');
const IDENTITY = require('./config/identity');

async function inspectSchedule() {
    const googleService = new GoogleService();
    const targetEmail = 'mikegauthierguillet@gmail.com';

    console.log(`[DEBUG] Connecting to ${targetEmail}...`);

    const auth = await googleService.getClient(targetEmail);
    if (!auth) {
        console.error("Auth failed");
        return;
    }

    const { google } = require('googleapis');
    const gmail = google.gmail({ version: 'v1', auth });

    try {
        // Search for SchedulePro emails
        const res = await gmail.users.messages.list({
            userId: 'me',
            q: 'from:SchedulePro OR subject:"SPRO"',
            maxResults: 1
        });

        const messages = res.data.messages;
        if (!messages || messages.length === 0) {
            console.log("Aucun email SchedulePro trouvé.");
            return;
        }

        const messageId = messages[0].id;
        console.log(`[DEBUG] Found message ID: ${messageId}`);

        const msg = await gmail.users.messages.get({
            userId: 'me',
            id: messageId,
            format: 'full'
        });

        const payload = msg.data.payload;
        const headers = payload.headers;
        const subject = headers.find(h => h.name === 'Subject')?.value;
        const date = headers.find(h => h.name === 'Date')?.value;

        console.log(`\n===== DÉTAILS DE L'HORAIRE =====`);
        console.log(`Sujet: ${subject}`);
        console.log(`Date: ${date}`);

        let body = "";
        if (payload.parts) {
            for (const part of payload.parts) {
                if (part.mimeType === 'text/plain' && part.body.data) {
                    body += Buffer.from(part.body.data, 'base64').toString('utf-8');
                }
            }
        } else if (payload.body.data) {
            body = Buffer.from(payload.body.data, 'base64').toString('utf-8');
        }

        // If body is empty, it might be HTML only. Let's try to get snippet at least or HTML part.
        if (!body && payload.parts) {
            for (const part of payload.parts) {
                if (part.mimeType === 'text/html' && part.body.data) {
                    // Just take a snippet of HTML if text is missing, or use the snippet field
                    console.log("[NOTE] Email is HTML only, showing snippet.");
                    console.log(msg.data.snippet);
                    return;
                }
            }
        }

        console.log("\n[CONTENU]");
        console.log(body || msg.data.snippet);

    } catch (error) {
        console.error("Erreur:", error);
    }
}

inspectSchedule();
