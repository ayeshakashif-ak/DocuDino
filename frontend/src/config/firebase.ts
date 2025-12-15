// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAnalytics } from "firebase/analytics";
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries

// Your web app's Firebase configuration
// For Firebase JS SDK v7.20.0 and later, measurementId is optional
const firebaseConfig = {
  apiKey: "AIzaSyA3eYYHuVNbcSR-8ZRQC_5cUWMonpvg_M0",
  authDomain: "docudino-auth-native.firebaseapp.com",
  projectId: "docudino-auth-native",
  storageBucket: "docudino-auth-native.firebasestorage.app",
  messagingSenderId: "1015291003856",
  appId: "1:1015291003856:web:19f6e6cbd1dea2203c2fd5",
  measurementId: "G-0XM3CG2TE9"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);

// Initialize Analytics (only in browser environment)
let analytics;
if (typeof window !== 'undefined') {
  analytics = getAnalytics(app);
}

export { app, analytics };
export default app;

