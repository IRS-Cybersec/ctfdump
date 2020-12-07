const fetch = require('node-fetch');

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// wordlist collected from the website
const words = ['digital', 'parking', 'data', 'information', 'architecture', 'wifi', 'smartcity', 'computer', 'efficiency', 'technology', 'payment', 'ai', 'fintech', 'analytics', 'applications', 'internet', 'cybersecurity', 'iot', 'innovation', 'systems', 'knowledge', 'communication', 'mobile', 'intelligent', 'wireless', 'the', 'people', 'who', 'crazy', 'enough', 'to', 'think', 'they', 'can', 'change', 'world', 'are', 'ones', 'do'];
(async () => {
    for (const word1 of words) {
        for (const word2 of words) {
            const res = await fetch(`https://${word1}-${word2}-s4fet3ch.s3-ap-southeast-1.amazonaws.com`);
            if (res.status != 404) {
                // this bucket exists!!
                console.log(`https://${word1}-${word2}-s4fet3ch.s3-ap-southeast-1.amazonaws.com`);
            }
            // avoid possible rate limiting
            await sleep(1000);
        }
    }
})();