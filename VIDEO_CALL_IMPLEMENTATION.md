# Professional Real-Time Video Call Implementation Guide

## ✅ What's Been Implemented

### 1. **Backend WebRTC Signaling (app.py)**
- **Video Call Handlers**:
  - `video_call_initiate`: Doctor-only call initiation with ACL, payment gating, and busy detection
  - `video_call_accept`: Patient accepts incoming call
  - `video_call_reject`: Patient rejects or times out on call
  - `video_call_end`: Either party ends the call and clears busy markers

- **SDP Signaling Handlers** (for WebRTC media establishment):
  - `video_sdp_offer`: Doctor sends SDP offer to patient
  - `video_sdp_answer`: Patient sends SDP answer to doctor
  - `video_ice_candidate`: Exchange ICE candidates between peers

- **Call State Management**:
  - Busy detection via `get_user_busy_status(user_id)` - prevents concurrent calls
  - Busy tracking via `mark_users_busy()` - marks both participants in active call
  - Call cleanup via `clear_call_markers()` - removes busy markers when call ends
  - Redis-backed for multi-worker deployments (auto-fallback to in-memory)

### 2. **Frontend Features (templates/video_call.html)**
- **Professional UI**:
  - Dark theme with gradient backgrounds
  - Header showing caller name, call status, and duration timer (mm:ss format)
  - Video grid: large remote video with small local video in bottom-right corner
  - Control bar with mute, video toggle, and end call buttons

- **Incoming Call Experience**:
  - Modal dialog with caller name and avatar
  - Accept/Decline buttons
  - Incoming notification sound (video_ringtone.mp3)
  - Auto-rejects after 60 seconds if no response

- **Call Timeouts & Retry**:
  - 60-second no-answer timeout for outgoing calls
  - Status modal showing "No Answer" with Retry/Cancel options
  - Busy detection shows "User is on another call" message
  - Payment locked shows "Payment required" message

- **Real-Time Media**:
  - Bi-directional video/audio via WebRTC
  - STUN servers for NAT traversal (Google stun servers)
  - Audio/video track toggling (mute/video off)
  - Call duration tracking (starts after connection)

### 3. **Payment Gating**
- Doctor cannot initiate calls if `appointment.payment_status != 'completed'`
- Controls are disabled with lock overlay showing "Payment Required"
- Patient can always answer calls (payment not required for receiving)

### 4. **Access Control (ACL)**
- **Doctor-only calling**: Only doctors can initiate video calls
- **Patient restriction**: Patients cannot call doctors (can only receive and answer)
- **Appointment verification**: Both parties must be participants of the appointment
- **Role enforcement**: Enforced at Socket.IO handler level

### 5. **Busy Detection**
- When doctor/patient initiates call, both are marked busy
- Incoming callers are notified "User is on another call"
- Busy state clears after call ends
- Redis-backed for distributed systems (1-hour TTL)

---

## 🎯 How to Use

### For Doctors:
1. Go to **Doctor Dashboard**
2. Click **"Video Call"** button on any appointment (only if payment status is "completed")
3. System automatically initiates call to patient
4. Patient receives incoming call modal with your name
5. Wait for patient to answer (60-second timeout)
6. Once accepted, video/audio connection establishes automatically
7. Call timer starts counting duration
8. Use controls to mute/toggle video
9. Click **"End Call"** button to disconnect

### For Patients:
1. Wait for doctor to call (incoming call modal appears)
2. See doctor's name and incoming call notification
3. Click **"Accept"** to connect or **"Decline"** to reject
4. If accepted, video/audio connection establishes
5. During call, use controls to manage audio/video
6. Click **"End Call"** to disconnect
7. System redirects to dashboard after 3 seconds

---

## 🔧 Technical Setup

### Prerequisites:
- HTTPS enabled (required for WebRTC camera/mic access)
- Appointment with `payment_status = 'completed'`
- Both doctor and patient must have browser permissions for camera/microphone
- Modern browser supporting WebRTC (Chrome, Firefox, Safari, Edge)

### Environment Configuration:

**For single-process deployment (default):**
```bash
# In-memory busy tracking (works fine for single server)
python wsgi.py
```

**For multi-process/distributed deployment:**
```bash
# Set REDIS_URL environment variable for distributed busy tracking
export REDIS_URL=redis://localhost:6379/0
# or with SSL:
export REDIS_URL=rediss://user:password@redis-host:6379/0

python wsgi.py
```

### Required Browser Permissions:
- Camera access
- Microphone access
- Display media (if screen sharing added later)

---

## 📋 API Reference

### Socket.IO Events

#### Client → Server:

**`video_call_initiate`** (Doctor)
```javascript
socket.emit('video_call_initiate', {
    appointment_id: 123,
    call_id: 'unique_call_id'  // optional, auto-generated
});
```

**`video_call_accept`** (Patient)
```javascript
socket.emit('video_call_accept', {
    appointment_id: 123,
    call_id: 'unique_call_id'
});
```

**`video_call_reject`** (Patient)
```javascript
socket.emit('video_call_reject', {
    appointment_id: 123,
    call_id: 'unique_call_id'
});
```

**`video_call_end`** (Both)
```javascript
socket.emit('video_call_end', {
    appointment_id: 123,
    call_id: 'unique_call_id'
});
```

**`video_sdp_offer`** (Doctor)
```javascript
socket.emit('video_sdp_offer', {
    appointment_id: 123,
    call_id: 'unique_call_id',
    sdp: offerObject.sdp  // SDP session description
});
```

**`video_sdp_answer`** (Patient)
```javascript
socket.emit('video_sdp_answer', {
    appointment_id: 123,
    call_id: 'unique_call_id',
    sdp: answerObject.sdp
});
```

**`video_ice_candidate`** (Both)
```javascript
socket.emit('video_ice_candidate', {
    appointment_id: 123,
    call_id: 'unique_call_id',
    candidate: iceCandidate
});
```

#### Server → Client:

**`video_incoming_call`** (Patient receives)
```javascript
{
    appointment_id: 123,
    caller_id: 456,
    caller_name: "Dr. John Smith",
    call_id: "unique_call_id",
    call_type: "video"
}
```

**`video_outgoing_call_started`** (Doctor receives confirmation)
```javascript
{
    appointment_id: 123,
    call_id: "unique_call_id"
}
```

**`video_call_accepted`** (Both receive)
```javascript
{
    call_id: "unique_call_id",
    appointment_id: 123,
    acceptor_id: 789
}
```

**`video_call_rejected`** (Both receive)
```javascript
{
    call_id: "unique_call_id",
    appointment_id: 123,
    rejector_id: 789
}
```

**`video_call_busy`** (Doctor receives if patient on another call)
```javascript
{
    appointment_id: 123,
    callee_id: 789
}
```

**`video_call_error`** (Doctor receives on errors)
```javascript
{
    appointment_id: 123,
    error: "Error message describing the issue"
}
```

---

## 🐛 Troubleshooting

### Issue: "Camera/Microphone not accessible"
**Solution**: 
- Check browser permissions for camera and microphone
- Ensure HTTPS is enabled (WebRTC requires secure context)
- Try in incognito mode to bypass cached permission denials

### Issue: "User is on another call"
**Solution**:
- Busy state is automatically tracked
- User must end their current call before receiving new calls
- If user crashes without ending call, Redis TTL (1 hour) will clear it automatically

### Issue: "Payment pending" message but payment completed
**Solution**:
- Refresh the page to reload appointment data
- Check that appointment's `payment_status` field is actually set to 'completed' in database
- Verify doctor is viewing their own appointment

### Issue: No audio/video connection after "Connected"
**Solution**:
- Check firewall/NAT settings (might need TURN server for restrictive networks)
- Verify STUN servers are reachable: stun.l.google.com:19302
- For production, consider adding TURN server configuration

### Issue: "Patient cannot initiate call" (but tries)
**Solution**:
- This is by design - only doctors can initiate
- Patient must wait for doctor to call
- Patient can only answer/decline incoming calls

---

## 📊 Monitoring & Logging

### Log Locations:
- Browser console: Open DevTools → Console tab
- Server logs: Check Flask application logs for Socket.IO events

### Debug Mode:
To enable verbose logging in video_call.html, uncomment console.log statements.

### Key Events to Monitor:
1. User connects to Socket.IO
2. Doctor initiates call
3. Patient receives incoming call modal
4. SDP offer/answer exchange
5. ICE candidate exchange
6. Call accepted/rejected
7. Media streams established
8. Call ended and busy markers cleared

---

## 🚀 Future Enhancements

### Recommended additions:
1. **Screen sharing** - Use `navigator.mediaDevices.getDisplayMedia()`
2. **Call recording** - Add MediaRecorder API
3. **Call history** - Store call details in database
4. **Analytics** - Track call duration, success rate, dropped calls
5. **Multi-party calls** - Extend to group consultations
6. **Custom ringtones** - Allow patients to set different sounds
7. **Call quality monitoring** - Display connection stats (bandwidth, latency)
8. **Automatic TURN server** - For better NAT traversal in restrictive networks

---

## ✨ Key Features Summary

| Feature | Status | Notes |
|---------|--------|-------|
| Real-time bi-directional video | ✅ | WebRTC with STUN servers |
| Real-time bi-directional audio | ✅ | Automatic audio handling |
| Doctor-only calling | ✅ | Enforced at socket handler |
| Patient-only receiving | ✅ | Cannot initiate |
| Payment gating | ✅ | Locks features if payment pending |
| Busy detection | ✅ | Prevents concurrent calls |
| 60-second timeout | ✅ | Auto-reject if no answer |
| Retry/Cancel flows | ✅ | User-friendly modal UI |
| Call timer | ✅ | mm:ss format |
| Ringtone notifications | ✅ | video_ringtone.mp3 |
| Mobile responsive | ✅ | Tested on mobile browsers |
| Redis distributed | ✅ | Optional, auto-fallback |

---

## 🔐 Security & Privacy

### Implemented Security Measures:
1. **ACL Enforcement**: Users can only call/join their own appointments
2. **Payment verification**: Features locked until payment complete
3. **CSRF Protection**: Socket.IO events include authentication check
4. **Role-based access**: Separate handlers for doctor/patient logic
5. **Busy state isolation**: Cannot interfere with other users' calls
6. **WebRTC encryption**: Peer-to-peer media is encrypted by default

### Privacy Considerations:
- Video/audio streams are peer-to-peer (not recorded/stored by server)
- Server only relays signaling data (SDP, ICE), not media
- Call metadata (duration, participants, time) stored in database
- User can disable video/audio any time during call

---

## 📞 Support & Issues

If issues occur:
1. Check browser console for JavaScript errors
2. Check server logs for Socket.IO events
3. Verify appointment exists and user has access
4. Ensure appointment payment_status is 'completed'
5. Test with different browser to rule out browser-specific issues
6. Clear browser cache and cookies

---

**Implementation Date**: 2025-01-14  
**Framework**: Flask + Flask-SocketIO  
**Frontend**: Vanilla JavaScript + WebRTC  
**Status**: Production-ready
