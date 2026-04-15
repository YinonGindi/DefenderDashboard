# How to Deploy the Defender Dashboard to Azure App Service

A step-by-step guide — no coding required, just clicking through the Azure Portal.

---

## What You Need Before Starting

- An **Azure subscription** (the account you use to log into portal.azure.com)
- The **defender-dashboard** folder on your computer containing:
  - `package.json`
  - `server.js`
  - `public/index.html`
- Do **NOT** include the `node_modules` folder — Azure will install dependencies automatically.

---

## PART 1: Create the App Service

1. Go to **https://portal.azure.com**
2. In the top search bar, type **"App Services"** and click on it
3. Click the **"+ Create"** button (top left)
4. Fill in the form:
   - **Subscription**: Pick your Azure subscription
   - **Resource Group**: Click "Create new" and name it `defender-dashboard-rg` (or use an existing one)
   - **Name**: Pick a unique name (e.g. `defender-dashboard-yourname`) — this becomes your URL: `https://defender-dashboard-yourname.azurewebsites.net`
   - **Publish**: Select **Code**
   - **Runtime stack**: Select **Node 20 LTS** (or the latest Node LTS available)
   - **Operating System**: Select **Linux**
   - **Region**: Pick the region closest to you
   - **Pricing plan**: Select **Basic B1** (cheapest option that works well) or Free F1 for testing
5. Click **"Review + create"**, then click **"Create"**
6. Wait for the deployment to finish (1-2 minutes), then click **"Go to resource"**

---

## PART 2: Turn On Managed Identity

This lets the app authenticate to Microsoft Graph without storing passwords.

1. In your App Service page, look at the **left menu**
2. Scroll down and click **"Identity"** (under the "Settings" section)
3. On the **"System assigned"** tab, flip the **Status** toggle to **On**
4. Click **"Save"**
5. A popup will ask you to confirm — click **"Yes"**
6. You'll see an **Object (principal) ID** appear — **copy this ID** (you'll need it in Part 3)

---

## PART 3: Give the App Permission to Query Microsoft Graph

This is the most important step — it grants the app access to run hunting queries.

### Option A: Using the Azure Portal (Cloud Shell)

1. In the Azure Portal, click the **Cloud Shell** icon (looks like `>_` in the top menu bar)
2. If asked, select **Bash**
3. Run these commands one at a time. Replace `YOUR_OBJECT_ID` with the ID you copied in Part 2:

```
# Step 1: Get the Microsoft Graph service principal ID
GRAPH_SP_ID=$(az ad sp list --filter "appId eq '00000003-0000-0000-c000-000000000000'" --query "[0].id" -o tsv)

# Step 2: Get the ThreatHunting.Read.All permission ID
ROLE_ID=$(az ad sp list --filter "appId eq '00000003-0000-0000-c000-000000000000'" --query "[0].appRoles[?value=='ThreatHunting.Read.All'].id" -o tsv)

# Step 3: Grant the permission to your app
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$GRAPH_SP_ID/appRoleAssignments" \
  --headers "Content-Type=application/json" \
  --body "{
    \"principalId\": \"YOUR_OBJECT_ID\",
    \"resourceId\": \"$GRAPH_SP_ID\",
    \"appRoleId\": \"$ROLE_ID\"
  }"
```

4. If successful, you'll see a JSON response — that means the permission is granted!

### Option B: Ask Your Azure Admin

If you don't have permission to run those commands, send your Azure admin this message:

> "Please grant the **ThreatHunting.Read.All** application permission on **Microsoft Graph** to the Managed Identity with Object ID: `YOUR_OBJECT_ID` for my App Service named `YOUR_APP_NAME`."

---

## PART 4: Upload Your Code

### Method A: ZIP Deploy (Easiest)

1. On your computer, go to the `defender-dashboard` folder
2. Select these files and folders:
   - `package.json`
   - `server.js`
   - `public/` (the entire folder)
3. **Right-click** → **"Compress to ZIP file"** (or "Send to → Compressed folder")
   - ⚠️ Make sure the files are at the **root** of the ZIP, NOT inside a subfolder
4. Go back to your App Service in the Azure Portal
5. In the left menu, click **"Advanced Tools"** (under "Development Tools")
6. Click **"Go →"** — this opens a new tab called "Kudu"
7. In the top menu of Kudu, click **"Tools"** → **"Zip Push Deploy"**
8. **Drag and drop** your ZIP file onto the page
9. Wait for it to finish uploading

### Method B: Using VS Code (If You Have It Installed)

1. Install the **"Azure App Service"** extension in VS Code
2. Open the `defender-dashboard` folder in VS Code
3. Click the **Azure icon** in the left sidebar
4. Find your App Service under "App Services"
5. Right-click it → **"Deploy to Web App..."**
6. Select the `defender-dashboard` folder when asked
7. Click **"Deploy"** when prompted

---

## PART 5: Configure the App

1. Go back to your App Service in the Azure Portal
2. In the left menu, click **"Configuration"** (under "Settings")
3. Click **"+ New application setting"** and add:
   - **Name**: `WEBSITE_NODE_DEFAULT_VERSION`
   - **Value**: `~20`
4. Click **OK**, then click **"Save"** at the top
5. Click **"Continue"** to confirm the restart

---

## PART 6: Verify It Works

1. In the left menu, click **"Overview"**
2. Find the **"Default domain"** — it looks like: `https://defender-dashboard-yourname.azurewebsites.net`
3. Click on the URL — your dashboard should load!
4. If you see **0** for all values — that's normal if permissions haven't propagated yet (wait 5-10 minutes and refresh)
5. If you see actual numbers — congratulations, everything is working! 🎉

---

## Troubleshooting

### Dashboard loads but all values show 0
- **Wait 5-10 minutes** — permission grants can take time to propagate
- Check that Part 3 (permissions) was completed successfully
- In the App Service left menu → "Log stream" to see if there are any errors

### Page doesn't load at all (error page)
- In the left menu, click **"Log stream"** and look for error messages
- Make sure you uploaded `package.json`, `server.js`, and `public/index.html`
- Make sure files are at the root of the ZIP (not inside a subfolder)

### "Application Error" or blank page
- Go to **"Advanced Tools"** → **"Go"** → in the top menu click **"Debug console"** → **"CMD"**
- Navigate to `site/wwwroot/` and verify all 3 files are there
- Try clicking **"Restart"** in the App Service Overview page

### Need to update the dashboard later?
- Just repeat **Part 4** with your updated files — it will overwrite the old ones

---

## Summary of What Was Set Up

| Component | Purpose |
|-----------|---------|
| **App Service** | Hosts and runs your dashboard website |
| **Managed Identity** | Lets the app authenticate to Microsoft without passwords |
| **ThreatHunting.Read.All** | Permission that allows running KQL hunting queries |
| **Node.js + Express** | The server that runs your dashboard backend |

Your dashboard URL: `https://YOUR-APP-NAME.azurewebsites.net`
