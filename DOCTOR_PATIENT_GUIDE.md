# Doctor & Patient Video Call Workflows

## For Doctors 👨‍⚕️

### How to Make a Video Call

#### Prerequisites:
- ✓ Logged in as doctor
- ✓ Appointment has `payment_status = "completed"`
- ✓ Both you and patient have camera & microphone access
- ✓ Browser HTTPS (required for WebRTC)

#### Step-by-Step:

1. **Go to Doctor Dashboard**
   - Navigate to `/doctor-dashboard` or click "Dashboard" in menu

2. **Find Appointment**
   - Look for appointment in your list
   - Check that payment status is "COMPLETED" (not "PENDING")

3. **Click Video Call Button**
   - Green "Video Call" button appears if payment is complete
   - Button is disabled/hidden if payment is still pending

4. **Prepare Your Setup**
   - Check lighting (face should be well-lit)
   - Minimize background distractions
   - Ensure quiet environment
   - Close other video apps

5. **Browser Permissions**
   - If prompted, click "Allow" for camera and microphone
   - This only happens once per browser

6. **See Your Video**
   - Small video appears in bottom-right corner (your video)
   - This confirms camera is working

7. **Ringing Starts**
   - You'll hear a ringtone sound
   - Status shows "Ringing..."
   - Timer shows how long you've been calling (counts up)

8. **Wait for Patient Response**
   - Max 60 seconds to wait
   - If patient doesn't answer within 60 seconds:
     - Ringtone stops
     - "No Answer" message appears
     - You can click "Retry" to call again
     - Or click "Cancel" to close

9. **Patient Answers**
   - You'll see patient's video appear (large, center screen)
   - Status changes to "Connected"
   - Call timer starts
   - You can now see and hear each other

10. **During the Call**
    - **Mute Button** (microphone icon)
      - Click to mute/unmute your microphone
      - Button color changes when muted
    - **Video Button** (camera icon)
      - Click to turn camera off/on
      - Button color changes when off
    - **End Call Button** (phone with slash)
      - Click to disconnect from call
      - Ends call for both doctor and patient

11. **After Call Ends**
    - All video stops
    - You're redirected to dashboard after 3 seconds
    - Call history is maintained

### Troubleshooting (Doctor)

| Issue | Solution |
|-------|----------|
| "Payment Required" overlay | Complete payment in admin dashboard first |
| "Video Call" button is grayed out | Payment status is pending - complete payment |
| Camera/microphone not working | Check browser permissions - allow access |
| No sound from ringtone | Check system volume, browser not muted |
| Patient not answering after 60s | Network issue? Try clicking "Retry" |
| "User is on another call" | Patient is in another call - try later |
| Video connection fails | Check HTTPS, firewall, or try different browser |

---

## For Patients 👩‍⚕️

### How to Receive a Video Call

#### Prerequisites:
- ✓ Logged in as patient
- ✓ Doctor initiates call to your appointment
- ✓ You have camera & microphone access
- ✓ Browser HTTPS (required for WebRTC)

#### Step-by-Step:

1. **Wait for Incoming Call**
   - You don't need to do anything to prepare
   - When doctor calls, notification appears automatically

2. **See Incoming Call Modal**
   - Large modal appears on your screen
   - Shows doctor's name
   - Shows "Incoming video call" message
   - You hear a notification sound

3. **Choose to Accept or Decline**
   - **Accept (Green Button)** = Start video call
   - **Decline (Red Button)** = Reject call

4. **Accept the Call** (If you want to take it)
   - Click "Accept" button
   - Browser may ask for camera/microphone permission
   - Click "Allow" if prompted
   - Modal closes
   - Your video stream starts (bottom-right corner)
   - Status shows "Connecting..." then "Connected"

5. **See Doctor's Video**
   - Doctor's video appears on main screen (large)
   - Your video appears in corner (small)
   - Timer starts counting call duration
   - You can now see and hear each other

6. **During the Call**
   - **Mute Button** (microphone icon)
     - Click to mute/unmute your microphone
     - Button changes color when muted
   - **Video Button** (camera icon)
     - Click to turn your camera off/on
     - Button changes color when off
   - **End Call Button** (phone with slash)
     - Click to hang up and disconnect
     - Ends call for both of you

7. **After Call Ends**
   - Video stops automatically
   - You're redirected to dashboard after 3 seconds
   - Call history maintained

8. **If You Decline the Call** (If you don't want to take it)
   - Click "Decline" button
   - Modal closes
   - Doctor is notified you declined
   - You return to normal screen

9. **If You Don't Answer (60 Seconds)**
   - If you see modal but don't click Accept/Decline for 60 seconds
   - Call automatically times out
   - Modal closes
   - Doctor sees "No Answer" and can retry

### What NOT To Do 🚫

- ❌ Do NOT try to initiate a video call (patients can't call doctors)
- ❌ Do NOT click "Video Call" in your dashboard (not available)
- ❌ Do NOT skip browser permission prompts (camera/mic won't work)
- ❌ Do NOT block camera/microphone in browser settings (call won't work)
- ❌ Do NOT close the browser during call (disconnects immediately)

### Troubleshooting (Patient)

| Issue | Solution |
|-------|----------|
| No incoming call modal appears | Check if browser is in background - bring to foreground |
| Hear notification but no modal | Refresh page, try logging out and back in |
| "Accept" button doesn't work | Check browser permissions for camera/microphone |
| No video from doctor | Wait 5 seconds for connection to establish |
| Doctor can hear you but you can't hear them | Check system volume, unmute browser tab |
| Video quality is poor | Check internet speed, close other apps using bandwidth |
| Call drops unexpectedly | Network issue - Doctor can click "Retry" |

---

## Common Questions

### Doctor Questions

**Q: Why can't I call this patient?**
A: Possible reasons:
- Payment status is "PENDING" (not "COMPLETED")
- Patient is already on another call
- Appointment doesn't exist or you don't have access
- Patient has blocked/refused the call

**Q: What if patient doesn't answer?**
A: After 60 seconds of ringing:
- You see "No Answer" message
- You can click "Retry" to call again
- Or click "Cancel" to close the call window

**Q: Can I call multiple patients at once?**
A: No. You can only be in one call at a time. The system prevents concurrent calls for safety.

**Q: What if my connection drops during call?**
A: The call will end. You can immediately initiate a new call to reconnect.

**Q: Can I record the call?**
A: Currently, recording is not built-in. The call video/audio is peer-to-peer and not stored on server.

**Q: What if patient has poor internet?**
A: The call will have:
- Choppy video (delayed)
- Degraded audio quality
- Possible disconnections
- System automatically uses lower quality for better stability

---

### Patient Questions

**Q: Why did I get a call? I didn't request it.**
A: Your doctor initiated the call. This is normal for follow-ups or check-ins.

**Q: What if I'm busy and can't take the call?**
A: Click "Decline" button. Doctor will be notified you declined.

**Q: What if I accidentally clicked "Decline"?**
A: Your doctor can click "Retry" to call you again immediately.

**Q: How long does a call last?**
A: As long as you need. You can end it anytime by clicking "End Call".

**Q: Can my doctor see anything besides video?**
A: No. They only see your video feed and hear your audio. They can't access files, documents, or anything else on your device.

**Q: What if I want to end the call?**
A: Click the "End Call" button (red phone with slash). The call will disconnect immediately.

**Q: Is my video/audio being recorded?**
A: No. The video/audio is only for this call. Nothing is stored on the server.

---

## Privacy & Security Information

### What Is Shared?
- ✓ Your real-time video stream (only during active call)
- ✓ Your real-time audio stream (only during active call)
- ✓ Call metadata (start time, duration, participants)

### What Is NOT Shared?
- ✗ Device files (documents, photos, etc.)
- ✗ Browser history
- ✗ Screen contents (unless you choose to share)
- ✗ Personal information beyond appointment details

### Security Features
- 🔒 All video/audio is encrypted
- 🔒 Only appointment participants can see each other
- 🔒 HTTPS required (secure connection)
- 🔒 Authentication required (login necessary)
- 🔒 Payment verification enforced (doctors can't bypass)

---

## Tips for Better Experience

### For Doctors

1. **Lighting**
   - Face the light source
   - Avoid backlighting (sitting in front of window)
   - Use ring light or desk lamp if available

2. **Background**
   - Keep professional background visible
   - Avoid cluttered or unprofessional backgrounds
   - Consider blurred background for privacy

3. **Audio**
   - Use microphone-equipped headphones for clarity
   - Minimize background noise (close windows/doors)
   - Speak clearly and at normal volume

4. **Network**
   - Use wired Ethernet if possible (more stable than WiFi)
   - Close bandwidth-heavy apps (streaming, downloads)
   - Avoid shared networks during call

5. **Setup**
   - Position camera at eye level
   - Sit arm's length from camera
   - Minimize camera movement

### For Patients

1. **Be Ready**
   - Keep camera/microphone accessible
   - Clear desk/area before call
   - Ensure quiet environment

2. **Respond Quickly**
   - Accept call within 60 seconds to avoid timeout
   - Have phone/device in hand so you don't miss call

3. **Privacy**
   - Take call in private location if discussing sensitive health info
   - Ensure family/roommates aren't visible if concerned

4. **Audio Quality**
   - Use headphones/earbuds for better privacy
   - Speak clearly
   - Minimize background noise

---

## Emergency Assistance

### If Something Goes Wrong:

1. **Refresh Page**
   - Sometimes fixes temporary connection issues
   - Try again after refreshing

2. **Check Internet**
   - Restart router if connection is slow
   - Switch to wired connection if available
   - Check WiFi signal strength

3. **Browser Issues**
   - Try different browser (Chrome, Firefox, Safari)
   - Clear browser cache and cookies
   - Restart browser and try again

4. **Contact Support**
   - If issue persists, contact administrator
   - Provide: error message, browser type, timestamp
   - Use contact form on website

---

**Version 1.0 | January 2025**
