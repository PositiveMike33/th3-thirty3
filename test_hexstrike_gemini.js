
async function testGeminiHexStrike() {
    console.log("Testing HexStrike Gemini Integration...");

    try {
        const response = await fetch('http://localhost:3000/api/hexstrike/chat', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                message: "List the available network reconnaissance tools you have access to."
            })
        });

        const data = await response.json();
        console.log("Response Status:", response.status);
        console.log("Response Body:", JSON.stringify(data, null, 2));
    } catch (error) {
        console.error("Error:", error);
    }
}

testGeminiHexStrike();
