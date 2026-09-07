from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.cache import never_cache
from django.urls import reverse
from .models import CustomUser
from .utils import generate_captcha, verify_captcha
import re
import time

@never_cache
def register_view(request):
    if request.user.is_authenticated:
        return redirect('profile')

    # Получаем сохранённые данные из сессии (если есть)
    saved_data = request.session.pop('register_form_data', {}) if request.method == 'GET' else {}

    if request.method == 'GET':
        captcha_data = generate_captcha(request)
        return render(request, 'register.html', {
            'captcha': captcha_data,
            'form_data': saved_data
        })

    # POST — форма отправлена
    username = request.POST.get('username', '').strip()
    email = request.POST.get('email', '').strip()
    password = request.POST.get('password', '')
    confirm_password = request.POST.get('confirm_password', '')
    captcha_answer = request.POST.get('captcha_answer', '')

    # 1. Проверяем капчу (старую)
    captcha_valid = verify_captcha(request, captcha_answer)

    # 2. ОБНОВЛЯЕМ капчу ПОСЛЕ проверки
    generate_captcha(request)

    # 3. Если капча неверна
    if not captcha_valid:
        messages.error(request, 'Неверный ответ капчи')
        request.session['register_form_data'] = {
            'username': username,
            'email': email
        }
        return redirect(f"{reverse('register')}?t={int(time.time())}")

    # 4. Валидация полей
    errors = []

    if not re.match(r'^[a-zA-Z0-9]{3,20}$', username):
        errors.append('Имя пользователя: только латиница и цифры, от 3 до 20 символов')

    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        errors.append('Введите корректный email')

    if len(password) < 6 or not re.search(r'[a-zA-Z]', password) or not re.search(r'[0-9]', password):
        errors.append('Пароль должен содержать минимум 6 символов, буквы и цифры')

    if password != confirm_password:
        errors.append('Пароли не совпадают')

    if CustomUser.objects.filter(username=username).exists():
        errors.append('Пользователь с таким именем уже существует')

    if CustomUser.objects.filter(email=email).exists():
        errors.append('Пользователь с таким email уже зарегистрирован')

    if errors:
        for error in errors:
            messages.error(request, error)
        request.session['register_form_data'] = {
            'username': username,
            'email': email
        }
        return redirect(f"{reverse('register')}?t={int(time.time())}")

    # Успех
    user = CustomUser.objects.create_user(
        username=username,
        email=email,
        password=password
    )
    messages.success(request, 'Регистрация успешна! Войдите в систему.')
    return redirect('login')


@never_cache
def login_view(request):
    if request.user.is_authenticated:
        return redirect('profile')

    saved_data = request.session.pop('login_form_data', {}) if request.method == 'GET' else {}

    if request.method == 'GET':
        captcha_data = generate_captcha(request)
        return render(request, 'login.html', {
            'captcha': captcha_data,
            'form_data': saved_data
        })

    # POST
    username_or_email = request.POST.get('username_or_email', '').strip()
    password = request.POST.get('password', '')
    captcha_answer = request.POST.get('captcha_answer', '')

    # 1. Проверяем капчу (старую)
    captcha_valid = verify_captcha(request, captcha_answer)

    # 2. ОБНОВЛЯЕМ капчу ПОСЛЕ проверки
    generate_captcha(request)

    # 3. Если капча неверна
    if not captcha_valid:
        messages.error(request, 'Неверный ответ капчи')
        request.session['login_form_data'] = {
            'username_or_email': username_or_email
        }
        return redirect(f"{reverse('login')}?t={int(time.time())}")

    # 4. Ищем пользователя
    user = None
    if '@' in username_or_email:
        try:
            user = CustomUser.objects.get(email=username_or_email)
        except CustomUser.DoesNotExist:
            pass
    else:
        try:
            user = CustomUser.objects.get(username=username_or_email)
        except CustomUser.DoesNotExist:
            pass

    # 5. Проверка пароля
    if user and user.check_password(password):
        login(request, user)
        return redirect('profile')
    else:
        messages.error(request, 'Неверный логин или пароль')
        request.session['login_form_data'] = {
            'username_or_email': username_or_email
        }
        return redirect(f"{reverse('login')}?t={int(time.time())}")


@login_required
def profile_view(request):
    user = request.user
    return render(request, 'profile.html', {
        'username': user.username,
        'email': user.email,
        'created_at': user.created_at,
        'role': 'Пользователь'
    })


def logout_view(request):
    logout(request)
    return redirect('login')