# Quick Start Testing Guide - Professional Video Calling

## 🚀 Getting Started

### Step 1: Ensure Payment is Completed
Before testing, make sure the appointment has `payment_status = 'completed'`:
```python
# In Python shell or Flask context
from app import db, Appointment
apt = Appointment.query.get(1)  # Get your test appointment
apt.payment_status = 'completed'
db.session.commit()
```

### Step 2: Start the Application
```bash
# Activate virtual environment
.\myenv\Scripts\Activate.ps1

# Start the Flask application
python wsgi.py
```

The server will be available at: `http://localhost:5000`

### Step 3: Prepare Two Browser Sessions
- **Browser 1**: Doctor's session
- **Browser 2**: Patient's session

---

## 📱 Test Scenarios

### Scenario 1: Successful Video Call

**Doctor's Session:**
1. Login as doctor account
2. Go to Doctor Dashboard
3. Find an appointment with `payment_status = 'completed'`
4. Click **"Video Call"** button
5. Observe:
   - ✅ Header shows patient name
   - ✅ Status shows "Ringing..."
   - ✅ Ringtone plays (audio should be heard)
   - ✅ Local video stream appears in bottom-right
   - ✅ Control bar is enabled (mute, video, end call buttons)

**Patient's Session (Simultaneously):**
1. Login as patient account
2. Incoming call modal should appear with doctor's name
3. Click **"Accept"** button
4. Observe:
   - ✅ Modal closes
   - ✅ Remote video stream appears (doctor's video)
   - ✅ Timer starts counting (00:00, 00:01, etc.)
   - ✅ Status shows "Connected"
   - ✅ Both can see and hear each other

**During Call:**
- Doctor can click **Mute** button to toggle microphone
- Doctor can click **Video** button to turn off/on camera
- Call timer continues incrementing on both sides
- Either can click **End Call** to disconnect

**After Call Ends:**
- ✅ All streams stop
- ✅ Both users redirected to their dashboards after 3 seconds

---

### Scenario 2: Patient Doesn't Answer (60-Second Timeout)

**Doctor's Session:**
1. Initiate call (like Scenario 1)
2. Don't answer from patient side
3. After 60 seconds:
   - ✅ Doctor sees status modal: "No Answer"
   - ✅ Ringtone stops
   - ✅ Modal shows "Retry" and "Cancel" buttons

**Retry Flow:**
- Click **"Retry"** to redial
- Call initiates again with new `call_id`
- Patient receives another incoming call modal

**Cancel Flow:**
- Click **"Cancel"** to close call window
- Redirects to dashboard

---

### Scenario 3: Patient Declines Call

**Patient's Session:**
1. See incoming call modal
2. Click **"Decline"** button
3. Observe:
   - ✅ Modal closes
   - ✅ Status shows "Call declined"

**Doctor's Session:**
1. See status modal: "Call Declined"
2. Options to retry or cancel

---

### Scenario 4: User Busy (Prevent Concurrent Calls)

**Setup:**
- Doctor initiates call to Patient A (call is accepted and active)
- Doctor tries to initiate call to Patient B

**Expected Behavior:**
- Doctor sees error: "User is on another call"
- Patient B does NOT receive incoming call
- Patient A remains in active call

---

### Scenario 5: Payment Not Completed

**Setup:**
- Doctor appointment has `payment_status = 'pending'` or other value

**Expected Behavior:**
1. Doctor dashboard "Video Call" button is disabled
2. Clicking opens video call page but shows:
   - ✅ Payment lock overlay
   - ✅ Lock icon with "Payment Required" message
   - ✅ Back button to return to dashboard

---

### Scenario 6: Doctor Attempts to Disable Payment Gating

**Attempt:** Patient initiates call (circumvent doctor-only restriction)

**Expected Behavior:**
1. Patient cannot find "Video Call" button on dashboard
2. If patient manually navigates to URL, server Socket.IO handler rejects with error
3. No incoming call appears on doctor's side

---

## 🎥 Verification Checklist

Use this checklist to verify all features are working:

### Media & Connection
- [ ] Local video appears on caller side immediately
- [ ] Remote video appears after call acceptance
- [ ] Bi-directional audio is clear
- [ ] Bi-directional video is smooth (no major lag)
- [ ] Local video is small (bottom-right corner)
- [ ] Remote video is large (main area)

### UI Elements
- [ ] Header shows correct caller name
- [ ] Timer starts at 00:00 and counts up (mm:ss format)
- [ ] Ringtone plays on incoming call (patient)
- [ ] Status messages update correctly
- [ ] Control buttons are clickable
- [ ] Modals appear/disappear correctly

### Call Control
- [ ] Mute button toggles microphone (button color changes)
- [ ] Video button toggles camera (button color changes)
- [ ] End Call button disconnects immediately
- [ ] Can toggle mute/video during active call

### Payment Gating
- [ ] Doctor cannot call with pending payment
- [ ] Lock overlay shows if payment not complete
- [ ] Patient can still receive calls during payment pending

### Busy Detection
- [ ] User on active call cannot receive second call
- [ ] Busy message shows correctly
- [ ] Busy state clears after call ends
- [ ] Can immediately make new call after previous one ends

### Timeouts & Retry
- [ ] No-answer timeout triggers at exactly 60 seconds
- [ ] No-answer modal shows with correct message
- [ ] Retry button redials successfully
- [ ] Cancel button closes call window
- [ ] Doctor-side timeout shows correct message

### Mobile Responsiveness
- [ ] Layout is responsive on tablet
- [ ] Layout is responsive on mobile phone
- [ ] Controls are still clickable on mobile
- [ ] No horizontal scroll on mobile

---

## 🔍 Debugging Tips

### Check Browser Console
```javascript
// In browser DevTools (F12) → Console tab:

// Check Socket.IO connection
socket.connected  // Should be 'true'

// Check call state
state.appointmentId   // Should be the appointment ID
state.callId          // Should be a unique call ID
state.peerConnection  // Should exist after media init
state.localStream     // Should have video/audio tracks
```

### Monitor Network Activity
1. Open DevTools → Network tab
2. Filter for WebSocket messages
3. Should see Socket.IO handshake, then event emissions
4. Look for: `video_incoming_call`, `video_sdp_offer`, `video_sdp_answer`, `video_ice_candidate`

### Check Browser Console Logs
```
Connected to WebSocket
Remote track received: video
Remote track received: audio
Connection state: connected
```

### Server-Side Debugging
Add these to Flask logs:
```python
@app.before_request
def log_request():
    print(f"[{datetime.now()}] {request.method} {request.path}")

# In Socket.IO handlers:
print(f"[VIDEO_CALL] User {current_user.id} initiated call to appointment {appointment_id}")
```

---

## 🚨 Common Issues & Solutions

### Issue: "No video connection after call accepted"
**Check:**
1. Are cameras/mics showing in browser permissions?
2. Is HTTPS enabled? (WebRTC requires secure context)
3. Are both users allowing camera/microphone access?
4. Check browser console for permission errors

**Fix:**
```
- Refresh page
- Check browser camera/mic permissions
- Try different browser
- Check System Preferences (macOS) or Settings (Windows)
```

### Issue: "Audio but no video"
**Check:**
1. Is video track enabled? (Click video button to verify toggle)
2. Is camera actually working? (Test in system settings)
3. Is there enough light? (WebRTC needs good lighting)

### Issue: "Call seems to hang after 'Ringing...' for doctor"
**Check:**
1. Is patient's page loading correctly?
2. Is Socket.IO connection established on patient's browser?
3. Does browser console show any errors?

### Issue: "Ringtone not playing"
**Check:**
1. Is browser volume muted?
2. Is audio allowed in browser permissions?
3. Does file exist: `/static/ringtones/video_ringtone.mp3`?
4. Try in different browser

### Issue: "Payment lock shows even though payment is completed"
**Fix:**
```
- Refresh the appointment details page
- Clear browser cache (Ctrl+Shift+Delete)
- Verify database: SELECT payment_status FROM appointments WHERE id=X;
```

---

## 📊 Performance Testing

### Measure Call Quality
**During an active call:**
1. Open DevTools → Performance/Network tab
2. Check bandwidth usage (should be <5 Mbps for video)
3. Check latency (hover over network requests)
4. Monitor CPU usage (should be <30% for video processing)

### Stress Test (Advanced)
1. Open 5 simultaneous browser tabs
2. Initiate calls between different pairs
3. Monitor for memory leaks or dropped calls
4. Server should remain responsive

---

## ✅ Pre-Production Checklist

Before deploying to production:

### Security
- [ ] HTTPS is enforced on all endpoints
- [ ] CSRF tokens are validated
- [ ] Rate limiting is in place for Socket.IO events
- [ ] User authentication is required
- [ ] ACL is properly enforced in all handlers

### Infrastructure
- [ ] Redis is configured for multi-worker deployments
- [ ] TURN server is configured (if needed)
- [ ] Firewall allows WebRTC ports (UDP 1024-65535)
- [ ] SSL certificates are valid and up-to-date

### Monitoring
- [ ] Error logging is in place
- [ ] Call metrics are being tracked
- [ ] Socket.IO connections are monitored
- [ ] Database queries are optimized

### Testing
- [ ] All scenarios in this guide have been tested
- [ ] Mobile browsers have been tested
- [ ] Network failures have been simulated
- [ ] Payment gating has been verified

---

## 📞 Testing Support

If you encounter issues:

1. **Collect Information:**
   - Browser type and version
   - Operating system
   - Error messages from console
   - Server log output
   - Screenshot of the issue

2. **Check Documentation:**
   - Review VIDEO_CALL_IMPLEMENTATION.md
   - Check troubleshooting section

3. **Enable Debug Mode:**
   - Uncomment console.log statements in video_call.html
   - Monitor server logs with verbose output
   - Use browser DevTools Network tab

---

**Version:** 1.0  
**Last Updated:** 2025-01-14  
**Status:** Production Ready
