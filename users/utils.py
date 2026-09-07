import random
from django.http import HttpRequest

def generate_captcha(request: HttpRequest) -> dict:
    """Генерирует капчу и сохраняет ответ в сессии."""
    a = random.randint(1, 10)
    b = random.randint(1, 10)
    operation = random.choice(['+', '-'])

    if operation == '+':
        result = a + b
        display = f"{a} + {b}"
    else:
        if a < b:
            a, b = b, a
        result = a - b
        display = f"{a} - {b}"

    request.session['captcha_result'] = result
    request.session['captcha_display'] = display

    return {'display': display}

def verify_captcha(request: HttpRequest, user_answer: str) -> bool:
    """Проверяет ответ капчи (НЕ обновляет её)."""
    saved_result = request.session.get('captcha_result')
    return str(saved_result) == str(user_answer) if saved_result is not None else False