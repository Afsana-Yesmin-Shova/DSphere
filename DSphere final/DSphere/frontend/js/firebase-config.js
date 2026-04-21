/**
 * DSphere — firebase-config.js
 * Initialize Firebase SDK — fill in your config values from
 * the Firebase Console (Project Settings → Your apps → Web app)
 *
 * This file is imported by all frontend pages that need Firebase.
 * Populated and wired in Phase 2.
 */

import { initializeApp }        from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js';
import { getAuth }              from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js';
import { getFirestore }         from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-firestore.js';
import { getStorage }           from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-storage.js';

const firebaseConfig = {
  apiKey:            "AIzaSyB_JPBkmo2TqFb_dYCjPZGPAejMRPxSwEc",
  authDomain:        "dsphere-uni.firebaseapp.com",
  projectId:         "dsphere-uni",
  storageBucket:     "dsphere-uni.firebasestorage.app",
  messagingSenderId: "620545810861",
  appId:            "1:620545810861:web:ce148c6c3c3f8f596b4124",
};

const app      = initializeApp(firebaseConfig);
const auth     = getAuth(app);
const db       = getFirestore(app);
const storage  = getStorage(app);

export { app, auth, db, storage };