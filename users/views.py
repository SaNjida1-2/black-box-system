from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth import logout as django_logout
from .forms import UserRegisterForm, UserUpdateForm, ProfileUpdateForm,ReportUserForm
from blog.models import Post, Notification
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.core.exceptions import PermissionDenied
from blog.models import Post
import random
from django.core.mail import send_mail

def register(request):
    if request.method == 'POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            messages.success(request, f'Your account has been created!\
                            You are now able to log in')
            return redirect('login')
    else:
        form = UserRegisterForm()
    
    context = {'form': form}
    template_name = 'users/register.html'
    
    return render(request, template_name, context)

def validate_username(request):
    username = request.GET.get('username',None)
    data = {
        'is_taken':User.objects.filter(username__iexact=username).exists()
    }
    print(data)
    return JsonResponse(data)


# @login_required
def profile(request,username=None):
    report_form = ReportUserForm()
    user =  get_object_or_404(User,username=username)
    post_list = Post.objects.filter(author=user).order_by('-id')
    post_count = post_list.count()
    page = request.GET.get('page', 1)
    paginator = Paginator(post_list, 4)
    try:
        posts = paginator.page(page)
    except PageNotAnInteger:
        posts = paginator.page(1)
    except EmptyPage:
        posts = paginator.page(paginator.num_pages)    
    
    context = {
        'report_form':report_form,
        'posts':posts,
        'user_id':user,
        'post_count':post_count,
    }
    template_name = 'users/profile.html'

    return render(request, template_name, context)

@login_required
def updateProfile(request):
    if request.method == 'POST':
        u_form = UserUpdateForm(request.POST, instance=request.user)
        p_form = ProfileUpdateForm(request.POST,
                                   request.FILES,
                                   instance=request.user.profile)
        if u_form.is_valid() and p_form.is_valid():
            u_form.save()
            p_form.save()
            messages.success(request, f'Your account has been updated!')
            return redirect('profile',username=request.user.username)
        else:
            messages.error(request, f'Username already exists or in use!')
            return redirect('profile-update')
    else:
        u_form = UserUpdateForm(instance=request.user)
        p_form = ProfileUpdateForm(instance=request.user.profile)
        context = {
            'u_form': u_form,
            'p_form': p_form,
        }
        template_name = 'users/update_profile.html'

        return render(request, template_name, context)


@login_required
def userFollowUnfollow(request,pk=None):
    current_user = request.user
    other_user = User.objects.get(pk=pk)

    if other_user not in current_user.profile.follows.all():
        current_user.profile.follows.add(other_user)
        other_user.profile.followers.add(current_user)
        
        notify = Notification.objects.create(sender=current_user,receiver=other_user,action="started following you.")

    else:
        current_user.profile.follows.remove(other_user)
        other_user.profile.followers.remove(current_user)
    return redirect('profile',username=other_user.username)


@login_required
def  change_password(request):
    if request.method == 'POST':
        form  =  PasswordChangeForm(data=request.POST, user=request.user)

        if form.is_valid():
            form.save()
            update_session_auth_hash(request, form.user)
            return redirect('profile',username=request.user.username)
        else:
            return redirect('change-password')
    else:
        form = PasswordChangeForm(user=request.user)
        args = {'form':form}
        return render(request, 'users/change_password.html',args)


def send_otp_email(user):
    # 1. Generate a random 6-digit OTP
    otp = str(random.randint(100000, 999999))
    
    # 2. Save it to the user's profile (we added this field earlier)
    user.profile.two_factor_secret = otp
    user.profile.save()
    
    # 3. Send the email
    send_mail(
        'BlackBox - Your Security OTP',
        f'Your 6-digit verification code is: {otp}. It is valid for this session.',
        'security@blackbox.com',
        [user.email],
        fail_silently=False,
    )

def two_factor_verify(request):
    if not request.user.is_authenticated:
        return redirect('login')

    # FORCE SEND: If no OTP exists or if they just arrived via GET request
    if request.method == 'GET' and not request.session.get('otp_sent'):
        send_otp_email(request.user)
        request.session['otp_sent'] = True # Prevents spamming emails on refresh
        messages.info(request, f"A security code has been sent to your terminal/email.")

    if request.method == 'POST':
        user_input = request.POST.get('otp')
        stored_otp = request.user.profile.two_factor_secret
        
        if user_input == stored_otp:
            request.session['2fa_verified'] = True
            request.session['otp_sent'] = False # Reset for next login
            request.user.profile.two_factor_secret = None 
            request.user.profile.save()
            return redirect('/')
        else:
            messages.error(request, "Invalid OTP.")
            
    return render(request, 'users/2fa_verify.html')


def logout_view(request):
    if request.user.is_authenticated:
        request.user.profile.two_factor_secret = None # Clear OTP
        request.user.profile.save()
    
    if '2fa_verified' in request.session:
        del request.session['2fa_verified']
    django_logout(request)
    return render(request, 'users/logout.html')

# This is your RBAC Decorator
def admin_only(view_func):
    def wrapper_func(request, *args, **kwargs):
        if request.user.profile.role == 'ADMIN':
            return view_func(request, *args, **kwargs)
        else:
            raise PermissionDenied
    return wrapper_func

@login_required
@admin_only
def security_audit(request):
    # 1. View all users (Requirement: "View all users")
    all_users = User.objects.all()
    user_count = all_users.count()
    
    # 2. Get all posts for integrity check
    all_posts = Post.objects.all()
    
    # 3. Simulate Integrity Check (Requirement: "Run integrity checks")
    # Later, Member 2 will put their real MAC verification logic here.
    integrity_results = []
    for post in all_posts:
        # In the final version, this will compare calculated MAC vs stored MAC
        integrity_results.append({
            'post': post,
            'status': 'SECURE', # Placeholder for real MAC check
            'encryption': 'ECC'
        })

    context = {
        'all_users': all_users,
        'user_count': user_count,
        'integrity_results': integrity_results,
    }
    return render(request, 'users/security_audit.html', context)