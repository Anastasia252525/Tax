# demo.py - автоматизированная демонстрация
import asyncio
import httpx
import json
from datetime import date


async def demo():
    base_url = "http://localhost:8000"

    print("=" * 60)
    print("DEMONSTRATION OF TAX CALCULATION SERVICE")
    print("=" * 60)

    async with httpx.AsyncClient() as client:
        # 1. Проверка здоровья
        print("\n1. Health check:")
        resp = await client.get(f"{base_url}/health")
        print(f"   Status: {resp.status_code}")
        print(f"   Response: {resp.json()}")

        # 2. Регистрация нового пользователя
        print("\n2. User registration:")
        user_data = {
            "email": "demo@university.edu",
            "password": "Demo123",
            "full_name": "Иванов Иван Иванович",
            "company_name": "ООО 'Демо'",
            "inn": "9876543210"
        }
        resp = await client.post(f"{base_url}/register", json=user_data)
        print(f"   Status: {resp.status_code}")
        if resp.status_code == 200:
            print("   ✓ User registered successfully")
            user = resp.json()
            print(f"   User ID: {user['id']}, Email: {user['email']}")

        # 3. Авторизация
        print("\n3. User login:")
        login_data = {
            "username": "demo@university.edu",
            "password": "Demo123"
        }
        resp = await client.post(
            f"{base_url}/login",
            data=login_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        print(f"   Status: {resp.status_code}")
        if resp.status_code == 200:
            token_data = resp.json()
            token = token_data["access_token"]
            print("   ✓ Login successful")
            print(f"   Token type: {token_data['token_type']}")

            # Устанавливаем заголовок авторизации
            headers = {"Authorization": f"Bearer {token}"}

            # 4. Создание налоговой формы
            print("\n4. Create tax form:")
            form_data = {
                "form_code": "НДС-1",
                "form_name": "Декларация по НДС",
                "description": "Ежеквартальная декларация по НДС",
                "tax_period": "quarter"
            }
            resp = await client.post(
                f"{base_url}/tax-forms/",
                json=form_data,
                headers=headers
            )
            print(f"   Status: {resp.status_code}")
            if resp.status_code == 200:
                form = resp.json()
                print(f"   ✓ Tax form created: {form['form_name']} (ID: {form['id']})")

                # 5. Получение всех форм
                print("\n5. Get all tax forms:")
                resp = await client.get(
                    f"{base_url}/tax-forms/",
                    headers=headers
                )
                forms = resp.json()
                print(f"   ✓ Found {len(forms)} tax forms")

                # 6. Создание дедлайна
                print("\n6. Create deadline:")
                deadline_data = {
                    "tax_form_id": form["id"],
                    "deadline_date": str(date.today()),
                    "status": "pending",
                    "comment": "Дедлайн по НДС за 1 квартал"
                }
                resp = await client.post(
                    f"{base_url}/deadlines/",
                    json=deadline_data,
                    headers=headers
                )
                if resp.status_code == 200:
                    deadline = resp.json()
                    print(f"   ✓ Deadline created: {deadline['deadline_date']}")

        print("\n" + "=" * 60)
        print("DEMONSTRATION COMPLETED SUCCESSFULLY")
        print("=" * 60)


if __name__ == "__main__":
    print("Starting demonstration...")
    print("Make sure the server is running on http://localhost:8000")
    asyncio.run(demo())