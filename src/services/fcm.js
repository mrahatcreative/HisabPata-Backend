const admin = require('firebase-admin');
const { prisma } = require('../config/database');

let initialized = false;

function initFcm() {
  if (initialized) return true;
  const serviceAccountPath = process.env.FCM_SERVICE_ACCOUNT_PATH;
  if (!serviceAccountPath) {
    console.warn('[FCM] FCM_SERVICE_ACCOUNT_PATH not set. Push notifications disabled.');
    return false;
  }
  try {
    const serviceAccount = require(serviceAccountPath);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    initialized = true;
    console.log('[FCM] Firebase Admin initialized');
    return true;
  } catch (e) {
    console.error('[FCM] Failed to initialize Firebase:', e.message);
    return false;
  }
}

async function sendPushNotification(userId, title, body, data = {}) {
  if (!initialized && !initFcm()) return;
  try {
    const tokens = await prisma.fcmToken.findMany({
      where: { userId },
      select: { token: true },
    });
    if (tokens.length === 0) return;

    const message = {
      notification: { title, body },
      data: { ...data, click_action: 'FLUTTER_NOTIFICATION_CLICK' },
      tokens: tokens.map(t => t.token),
    };

    const response = await admin.messaging().sendEachForMulticast(message);
    const failedTokens = [];
    response.responses.forEach((resp, idx) => {
      if (!resp.success) {
        failedTokens.push(tokens[idx].token);
      }
    });
    if (failedTokens.length > 0) {
      await prisma.fcmToken.deleteMany({
        where: { token: { in: failedTokens } },
      });
      console.warn(`[FCM] Removed ${failedTokens.length} invalid token(s)`);
    }
  } catch (e) {
    console.error('[FCM] Send error:', e.message);
  }
}

async function sendPushNotificationToMultipleUserIds(userIds, title, body, data = {}) {
  for (const userId of userIds) {
    await sendPushNotification(userId, title, body, data);
  }
}

module.exports = { sendPushNotification, sendPushNotificationToMultipleUserIds, initFcm };
