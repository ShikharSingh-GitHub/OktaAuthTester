require("dotenv").config();
const axios = require("axios");

async function testToken() {
  try {
    console.log("Testing Okta API token...");
    console.log("OKTA_ORG_URL:", process.env.OKTA_ORG_URL);
    console.log("OKTA_API_TOKEN:", process.env.OKTA_API_TOKEN ? "SET" : "NOT SET");
    
    // Test basic API access
    const response = await axios.get(
      `${process.env.OKTA_ORG_URL}/api/v1/users/me`,
      {
        headers: {
          Authorization: `SSWS ${process.env.OKTA_API_TOKEN}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    console.log("✅ Token works! User info:", response.data.profile.email);
    
    // Test groups access
    const groupsResponse = await axios.get(
      `${process.env.OKTA_ORG_URL}/api/v1/users/${response.data.id}/groups`,
      {
        headers: {
          Authorization: `SSWS ${process.env.OKTA_API_TOKEN}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    console.log("✅ Groups access works! User groups:", groupsResponse.data.map(g => g.profile.name));
    
  } catch (error) {
    console.error("❌ Token test failed:");
    if (error.response) {
      console.error("Status:", error.response.status);
      console.error("Data:", error.response.data);
    } else {
      console.error("Error:", error.message);
    }
  }
}

testToken();
