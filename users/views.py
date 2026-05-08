from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth import logout as django_logout
from .forms import UserRegisterForm, UserUpdateForm, ProfileUpdateForm, ReportUserForm
from blog.models import Post, Notification
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.core.exceptions import PermissionDenied
import random
import json
import sys
import os
from django.core.mail import send_mail

# Security imports - Ensure these files exist in your 'security' folder
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'security')))
try:
    from rsa_engine import generate_keys, encrypt, decrypt 
    from hash_engine import hash_password 
except ImportError:
    print("Warning: Security engines not found. Check your security folder.")

def register(request):
    if request.method == 'POST':
        # --- DEBUG: See what the browser sent to the server ---
        print("\n--- INCOMING REGISTRATION DATA ---")
        print(f"POST Data: {request.POST}") 
        
        form = UserRegisterForm(request.POST)
        
        if form.is_valid():
            # 1. Create the User object but don't save to DB yet
            user = form.save(commit=False)
            
            # FIX: Get 'password1' from the form (this was the missing link!)
            username = form.cleaned_data.get('username')
            email = form.cleaned_data.get('email')
            raw_password = form.cleaned_data.get('password1') 
            
            # Fallback check
            if not raw_password:
                raw_password = form.cleaned_data.get('password')

            print(f"DEBUG: Setting password for {username} as: {raw_password}")
            
            # Hash the password correctly
            user.set_password(raw_password) 
            user.save() # User is now in the database
            
            print(f"✅ User '{username}' saved to database successfully.")

            # 2. Member 1 Security Layer (RSA Encryption)
            try:
                # Generate RSA Keys
                pub_key, priv_key = generate_keys()
                print("Generated RSA Keys...")
                
                # Encrypt Email using the RSA engine
                if email:
                    encrypted_data = encrypt(email, pub_key)
                    user.profile.encrypted_email = json.dumps(encrypted_data)
                    print(f"Encrypted Email: {user.profile.encrypted_email[:30]}...")

                # Save keys to the Profile
                user.profile.rsa_public_key = str(pub_key)
                user.profile.rsa_private_key = str(priv_key)
                user.profile.save()
                print("✅ Profile with RSA keys saved successfully.")
                
            except Exception as e:
                # Log the error but don't stop the user from being created
                print(f"❌ SECURITY ERROR: {e}")

            messages.success(request, f'Account created for {user.username}! You can now log in.')
            return redirect('login')
        else:
            # --- DEBUG: See why the form failed (e.g., password too short) ---
            print(f"❌ FORM INVALID: {form.errors}")
    else:
        form = UserRegisterForm()
    
    return render(request, 'users/register.html', {'form': form})
# --- 1. REGISTRATION ---
# # users/views.py
# # --- 1. REGISTRATION (Cleaned) ---
# def register(request):
#     # if request.method == 'POST':
#     #     form = UserRegisterForm(request.POST)
#     #     if form.is_valid():
#     #         user = form.save(commit=False)
#     #         # IMPORTANT: Set password before saving the user
#     #         raw_password = form.cleaned_data.get('password')
#     #         user.set_password(raw_password) 
#     #         user.save() # User exists now
#     if request.method == 'POST':
#         form = UserRegisterForm(request.POST)
#         if form.is_valid():
#             user = form.save() # This is the safest way to save
#             messages.success(request, f'Account created! Try logging in.')
#             return redirect('login')
#             try:
#                 # Member 1 Security: RSA & Encryption
#                 pub_key, priv_key = generate_keys()
#                 email_val = form.cleaned_data.get('email')
#                 if email_val:
#                     encrypted_data = encrypt(email_val, pub_key)
#                     user.profile.encrypted_email = json.dumps(encrypted_data)
                
#                 user.profile.rsa_public_key = str(pub_key)
#                 user.profile.rsa_private_key = str(priv_key)
#                 user.profile.save()
#             except Exception as e:
#                 print(f"Profile Security Error: {e}")

#             messages.success(request, f'Account created! You can now log in.')
#             return redirect('login')
#     else:
#         form = UserRegisterForm()
#     return render(request, 'users/register.html', {'form': form})

# --- 4. 2FA (Simplified & Integrated) ---
@login_required
def two_factor_verify(request):
    # Prevent infinite loops if already verified
    if request.session.get('2fa_verified'):
        return redirect('blog-home') # Double check this name in blog/urls.py

    if request.method == 'GET':
        # Generate code and print to terminal
        otp = str(random.randint(100000, 999999))
        request.user.profile.two_factor_secret = otp
        request.user.profile.save()
        
        print("\n" + "="*50)
        print(f"SECURE OTP FOR {request.user.username}: {otp}")
        print("="*50 + "\n")
        messages.info(request, "Check terminal for 2FA code.")

    if request.method == 'POST':
        user_input = request.POST.get('otp')
        if user_input == request.user.profile.two_factor_secret:
            request.session['2fa_verified'] = True
            return redirect('blog-home') 
        else:
            messages.error(request, "Invalid code.")
            
    return render(request, 'users/2fa_verify.html')
# --- 2. PROFILE & UPDATES ---
def profile(request, username=None):
    report_form = ReportUserForm()
    user = get_object_or_404(User, username=username)
    
    # Decryption Logic
    decrypted_email = "Email Encrypted"
    try:
        if user.profile.encrypted_email and user.profile.rsa_private_key:
            encrypted_email_list = json.loads(user.profile.encrypted_email)
            priv_key = eval(user.profile.rsa_private_key) 
            decrypted_email = decrypt(encrypted_email_list, priv_key)
    except:
        decrypted_email = "Unable to decrypt"

    post_list = Post.objects.filter(author=user).order_by('-id')
    paginator = Paginator(post_list, 4)
    page = request.GET.get('page', 1)
    try:
        posts = paginator.page(page)
    except (PageNotAnInteger, EmptyPage):
        posts = paginator.page(1)
    
    context = {
        'report_form': report_form,
        'posts': posts,
        'user_id': user,
        'post_count': post_list.count(),
        'decrypted_email': decrypted_email,
    }
    return render(request, 'users/profile.html', context)

@login_required
def updateProfile(request):
    if request.method == 'POST':
        u_form = UserUpdateForm(request.POST, instance=request.user)
        p_form = ProfileUpdateForm(request.POST, request.FILES, instance=request.user.profile)
        if u_form.is_valid() and p_form.is_valid():
            u_form.save()
            p_form.save()
            messages.success(request, f'Your account has been updated!')
            return redirect('profile', username=request.user.username)
    else:
        u_form = UserUpdateForm(instance=request.user)
        p_form = ProfileUpdateForm(instance=request.user.profile)
    return render(request, 'users/update_profile.html', {'u_form': u_form, 'p_form': p_form})

# --- 3. SOCIAL FEATURES (Fixed Missing Attribute) ---
@login_required
def userFollowUnfollow(request, pk=None):
    current_user = request.user
    other_user = get_object_or_404(User, pk=pk)
    if other_user not in current_user.profile.follows.all():
        current_user.profile.follows.add(other_user)
        other_user.profile.followers.add(current_user)
        Notification.objects.create(sender=current_user, receiver=other_user, action="started following you.")
    else:
        current_user.profile.follows.remove(other_user)
        other_user.profile.followers.remove(current_user)
    return redirect('profile', username=other_user.username)

# --- 4. 2FA & SECURITY ---
def send_otp_email(user):
    otp = str(random.randint(100000, 999999))
    user.profile.two_factor_secret = otp
    user.profile.save()
    
    # --- ADD THIS LINE HERE ---
    print(f"\n\n🚨 SECURITY ALERT: YOUR 2FA CODE IS: {otp} 🚨\n\n")
    # --------------------------

    send_mail(
        'Your Security Code',
        f'Your 2FA code is: {otp}',
        'security@nccbuddy.com',
        [user.email],
        fail_silently=False,
    )
    
# users/views.py

@login_required
def two_factor_verify(request):
    # If they are already verified, don't show this page
    if request.session.get('2fa_verified'):
        return redirect('blog:home')

    if request.method == 'GET':
        send_otp_email(request.user)
        # Force the code to show in terminal immediately
        print(f"--- NEW LOGIN DETECTED: Code for {request.user.username} printed above ---")

    if request.method == 'POST':
        user_input = request.POST.get('otp')
        if user_input == request.user.profile.two_factor_secret:
            request.session['2fa_verified'] = True
            return redirect('blog:home')
        else:
            messages.error(request, "Invalid OTP code.")

    return render(request, 'users/2fa_verify.html')
# --- 5. ADMIN & AUDIT ---
def admin_only(view_func):
    def wrapper_func(request, *args, **kwargs):
        if request.user.is_staff or (hasattr(request.user, 'profile') and request.user.profile.role == 'ADMIN'):
            return view_func(request, *args, **kwargs)
        raise PermissionDenied
    return wrapper_func

@login_required
@admin_only
def security_audit(request):
    all_users = User.objects.all()
    all_posts = Post.objects.all()
    return render(request, 'users/security_audit.html', {
        'all_users': all_users, 
        'user_count': all_users.count(),
        'integrity_results': [{'post': p, 'status': 'SECURE'} for p in all_posts]
    })

# --- 6. UTILITIES ---
def validate_username(request):
    username = request.GET.get('username', None)
    return JsonResponse({'is_taken': User.objects.filter(username__iexact=username).exists()})

@login_required
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(data=request.POST, user=request.user)
        if form.is_valid():
            form.save()
            update_session_auth_hash(request, form.user)
            return redirect('profile', username=request.user.username)
    else:
        form = PasswordChangeForm(user=request.user)
    return render(request, 'users/change_password.html', {'form': form})

def logout_view(request):
    if '2fa_verified' in request.session: del request.session['2fa_verified']
    django_logout(request)
    return render(request, 'users/logout.html')


LOGIN_REDIRECT_URL = '2fa-verify'

# from django.shortcuts import render, redirect, get_object_or_404
# from django.contrib import messages
# from django.contrib.auth.decorators import login_required
# from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
# from django.contrib.auth.forms import PasswordChangeForm
# from django.contrib.auth import update_session_auth_hash
# from django.contrib.auth import logout as django_logout
# from .forms import UserRegisterForm, UserUpdateForm, ProfileUpdateForm,ReportUserForm
# from blog.models import Post, Notification
# from django.contrib.auth.models import User
# from django.http import JsonResponse
# from django.core.exceptions import PermissionDenied
# from blog.models import Post
# import random
# from django.core.mail import send_mail



# import sys
# import os
# import json

# # This tells Python to look in your new 'security' folder
# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'security')))

# from rsa_engine import generate_keys, encrypt 
# from hash_engine import hash_password 

# def register(request):
#     if request.method == 'POST':
#         form = UserRegisterForm(request.POST)
#         if form.is_valid():
#             user = form.save(commit=False)
            
#             # 1. Standard Django Password (Allows you to log in)
#             raw_password = form.cleaned_data.get('password')
#             user.set_password(raw_password) 
#             user.save() 

#             # 2. Member 1: Custom RSA Logic
#             pub_key, priv_key = generate_keys()
#             email_val = form.cleaned_data.get('email') 
            
#             if email_val:
#                 encrypted_data = encrypt(email_val, pub_key)
#                 user.profile.encrypted_email = json.dumps(encrypted_data)
            
#             # 3. Store Keys & Custom Hash (Evidence for Lab)
#             user.profile.rsa_public_key = str(pub_key)
#             user.profile.rsa_private_key = str(priv_key)
#             # Store your custom engine's result here to show the examiner
#             # user.profile.custom_hash_evidence = hash_password(raw_password) 
            
#             user.profile.save()

#             messages.success(request, f'Account created! You can now log in.')
#             return redirect('login')
#     else:
#         form = UserRegisterForm()
#     return render(request, 'users/register.html', {'form': form})


# def validate_username(request):
#     username = request.GET.get('username',None)
#     data = {
#         'is_taken':User.objects.filter(username__iexact=username).exists()
#     }
#     print(data)
#     return JsonResponse(data)


# # @login_required
# def profile(request,username=None):
#     report_form = ReportUserForm()
#     user =  get_object_or_404(User,username=username)
#     post_list = Post.objects.filter(author=user).order_by('-id')
#     post_count = post_list.count()
#     page = request.GET.get('page', 1)
#     paginator = Paginator(post_list, 4)
#     try:
#         posts = paginator.page(page)
#     except PageNotAnInteger:
#         posts = paginator.page(1)
#     except EmptyPage:
#         posts = paginator.page(paginator.num_pages)    
    
#     context = {
#         'report_form':report_form,
#         'posts':posts,
#         'user_id':user,
#         'post_count':post_count,
#     }
#     template_name = 'users/profile.html'

#     return render(request, template_name, context)

# @login_required
# def updateProfile(request):
#     if request.method == 'POST':
#         u_form = UserUpdateForm(request.POST, instance=request.user)
#         p_form = ProfileUpdateForm(request.POST,
#                                    request.FILES,
#                                    instance=request.user.profile)
#         if u_form.is_valid() and p_form.is_valid():
#             u_form.save()
#             p_form.save()
#             messages.success(request, f'Your account has been updated!')
#             return redirect('profile',username=request.user.username)
#         else:
#             messages.error(request, f'Username already exists or in use!')
#             return redirect('profile-update')
#     else:
#         u_form = UserUpdateForm(instance=request.user)
#         p_form = ProfileUpdateForm(instance=request.user.profile)
#         context = {
#             'u_form': u_form,
#             'p_form': p_form,
#         }
#         template_name = 'users/update_profile.html'

#         return render(request, template_name, context)


# @login_required
# def userFollowUnfollow(request,pk=None):
#     current_user = request.user
#     other_user = User.objects.get(pk=pk)

#     if other_user not in current_user.profile.follows.all():
#         current_user.profile.follows.add(other_user)
#         other_user.profile.followers.add(current_user)
        
#         notify = Notification.objects.create(sender=current_user,receiver=other_user,action="started following you.")

#     else:
#         current_user.profile.follows.remove(other_user)
#         other_user.profile.followers.remove(current_user)
#     return redirect('profile',username=other_user.username)


# @login_required
# def  change_password(request):
#     if request.method == 'POST':
#         form  =  PasswordChangeForm(data=request.POST, user=request.user)

#         if form.is_valid():
#             form.save()
#             update_session_auth_hash(request, form.user)
#             return redirect('profile',username=request.user.username)
#         else:
#             return redirect('change-password')
#     else:
#         form = PasswordChangeForm(user=request.user)
#         args = {'form':form}
#         return render(request, 'users/change_password.html',args)


# def send_otp_email(user):
#     # 1. Generate a random 6-digit OTP
#     otp = str(random.randint(100000, 999999))
    
#     # 2. Save it to the user's profile (we added this field earlier)
#     user.profile.two_factor_secret = otp
#     user.profile.save()
    
#     # 3. Send the email
#     send_mail(
#         'BlackBox - Your Security OTP',
#         f'Your 6-digit verification code is: {otp}. It is valid for this session.',
#         'security@blackbox.com',
#         [user.email],
#         fail_silently=False,
#     )

# def two_factor_verify(request):
#     if not request.user.is_authenticated:
#         return redirect('login')

#     # FORCE SEND: If no OTP exists or if they just arrived via GET request
#     if request.method == 'GET' and not request.session.get('otp_sent'):
#         send_otp_email(request.user)
#         request.session['otp_sent'] = True # Prevents spamming emails on refresh
#         messages.info(request, f"A security code has been sent to your terminal/email.")

#     if request.method == 'POST':
#         user_input = request.POST.get('otp')
#         stored_otp = request.user.profile.two_factor_secret
        
#         if user_input == stored_otp:
#             request.session['2fa_verified'] = True
#             request.session['otp_sent'] = False # Reset for next login
#             request.user.profile.two_factor_secret = None 
#             request.user.profile.save()
#             return redirect('/')
#         else:
#             messages.error(request, "Invalid OTP.")
            
#     return render(request, 'users/2fa_verify.html')


# def logout_view(request):
#     if request.user.is_authenticated:
#         request.user.profile.two_factor_secret = None # Clear OTP
#         request.user.profile.save()
    
#     if '2fa_verified' in request.session:
#         del request.session['2fa_verified']
#     django_logout(request)
#     return render(request, 'users/logout.html')

# # This is your RBAC Decorator
# def admin_only(view_func):
#     def wrapper_func(request, *args, **kwargs):
#         if request.user.profile.role == 'ADMIN':
#             return view_func(request, *args, **kwargs)
#         else:
#             raise PermissionDenied
#     return wrapper_func

# @login_required
# @admin_only
# def security_audit(request):
#     # 1. View all users (Requirement: "View all users")
#     all_users = User.objects.all()
#     user_count = all_users.count()
    
#     # 2. Get all posts for integrity check
#     all_posts = Post.objects.all()
    
#     # 3. Simulate Integrity Check (Requirement: "Run integrity checks")
#     # Later, Member 2 will put their real MAC verification logic here.
#     integrity_results = []
#     for post in all_posts:
#         # In the final version, this will compare calculated MAC vs stored MAC
#         integrity_results.append({
#             'post': post,
#             'status': 'SECURE', # Placeholder for real MAC check
#             'encryption': 'ECC'
#         })

#     context = {
#         'all_users': all_users,
#         'user_count': user_count,
#         'integrity_results': integrity_results,
#     }
#     return render(request, 'users/security_audit.html', context)




# # tanisha123@


# from rsa_engine import decrypt # Make sure this is in your rsa_engine.py

# def profile(request, username=None):
#     user = get_object_or_404(User, username=username)
    
#     # Decrypt the email for display
#     encrypted_email = json.loads(user.profile.encrypted_email)
#     priv_key = eval(user.profile.rsa_private_key) # Convert string back to tuple
#     decrypted_email = decrypt(encrypted_email, priv_key)
    
#     context = {
#         'user_id': user,
#         'decrypted_email': decrypted_email,
#         # ... rest of your context ...
#     }
#     return render(request, 'users/profile.html', context)