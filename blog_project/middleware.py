import datetime
from django.conf import settings
from django.contrib import auth
from django.shortcuts import redirect

class SessionTimeoutMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            # 1. --- 2FA GATEKEEPER ---
            # Define paths that users are allowed to visit without being 2FA verified
            # We must include '2fa-verify' and 'logout' to prevent redirect loops
            allowed_paths = ['/2fa-verify/', '/account/logout/', '/logout/']
            
            if not request.session.get('2fa_verified') and request.path not in allowed_paths:
                return redirect('2fa-verify')

            # 2. --- SESSION TIMEOUT (15 Minutes) ---
            last_activity = request.session.get('last_activity')
            if last_activity:
                last_activity_time = datetime.datetime.fromisoformat(last_activity)
                elapsed_time = (datetime.datetime.now() - last_activity_time).seconds
                
                # 900 seconds = 15 minutes
                if elapsed_time > 900:
                    auth.logout(request)
                    # Clear 2FA status on timeout for safety
                    if '2fa_verified' in request.session:
                        del request.session['2fa_verified']
                    return redirect('login')

            # Update timestamp only if they are verified or on the 2FA page
            request.session['last_activity'] = datetime.datetime.now().isoformat()
        
        return self.get_response(request)
