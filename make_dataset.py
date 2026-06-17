"""
Generate a balanced 200-sample evaluation dataset (100 phishing / 100 legit).

NOTE: These are SYNTHETIC but realistic messages for pipeline validation and the
exhibit results display. For the research paper, supplement with REAL collected
screenshots/messages — synthetic data can flatter a rule-based detector.

Output: ground_truth_200.csv  (same schema as ground_truth.csv)
Reproducible (fixed random seed).
"""
import csv
import random

random.seed(42)

banks = ["GCash", "BDO", "BPI", "Metrobank", "PayMaya", "UnionBank", "Landbank", "RCBC"]
couriers = ["LBC", "J&T Express", "Lazada", "Shopee", "Ninja Van", "DHL", "Grab"]
services = ["Netflix", "Spotify", "Disney+", "Amazon Prime", "HBO Max"]
brands = ["Shopee", "Lazada", "Globe", "Smart", "SM", "Jollibee", "PLDT"]
merchants = ["Shopee", "Lazada", "SM Store", "Jollibee", "National Bookstore", "Watsons"]
names = ["Maria Santos", "John Cruz", "Anna Reyes", "Mark Lim", "Grace Tan", "Paolo Garcia"]
dates = ["June 18", "July 2", "Monday", "tomorrow", "next Friday", "Aug 5"]
times = ["9:00 AM", "2:30 PM", "10 AM", "4 PM", "3:00 PM"]

bad_bases = ["gcash-verify", "bdo-secure", "lbc-redelivery", "claim-prize-now",
             "account-update", "paymaya-login", "secure-billing", "ph-rewards", "unioalert"]
bad_tlds = [".xyz", ".top", ".info", ".online", ".club", ".tk"]


def amt():
    return f"{random.choice([350, 500, 999, 1500, 2999, 5000, 12500, 28000, 50000]):,}"


def code():
    return str(random.randint(100000, 999999))


def phone():
    return "+639" + "".join(str(random.randint(0, 9)) for _ in range(9))


def bad_url():
    scheme = random.choice(["http://", "https://", "http://www."])
    return f"{scheme}{random.choice(bad_bases)}{random.choice(bad_tlds)}/verify"


# --- Phishing templates (label 1) ---
phishing = [
    lambda: f"URGENT: Your {random.choice(banks)} account has been suspended due to unusual activity. Verify now to avoid permanent closure: {bad_url()}",
    lambda: f"{random.choice(banks)}: We detected a login from a new device. Confirm your identity within 24 hours or your account will be locked: {bad_url()}",
    lambda: f"Your {random.choice(couriers)} parcel is on hold. A customs fee of PHP {amt()} is required to release it. Pay here: {bad_url()}",
    lambda: f"Final notice: delivery failed. Update your address and settle the PHP {amt()} redelivery fee: {bad_url()}",
    lambda: f"Congratulations! You have been selected to win PHP {amt()} in the {random.choice(brands)} anniversary raffle. Claim your prize: {bad_url()}",
    lambda: f"Hi, we are hiring home-based staff. Earn PHP {amt()} daily just by liking videos. Message our HR on WhatsApp: {phone()}",
    lambda: f"Microsoft Security Alert: Your computer is infected with a virus. Call our toll-free support {phone()} immediately.",
    lambda: f"We noticed a login attempt on your account. Reply with the OTP {code()} we just sent to cancel this request.",
    lambda: f"Please process an urgent wire transfer of PHP {amt()} to our new supplier today. Keep this confidential. - {random.choice(names)}, CEO",
    lambda: f"Dear Beneficiary, I am a barrister handling a deceased client's estate worth ${random.randint(2, 15)}M. You are the next of kin. Contact me to claim your compensation.",
    lambda: f"Your {random.choice(services)} subscription payment was declined. Update your billing details now to avoid losing access: {bad_url()}",
    lambda: f"Your e-wallet has been temporarily limited. Re-verify your account here to restore full access: {bad_url()}",
    lambda: f"ALERT: an unauthorized transaction of PHP {amt()} was detected. If this wasn't you, secure your account immediately: {bad_url()}",
    lambda: f"You have an unclaimed refund of PHP {amt()} from {random.choice(brands)}. Confirm your bank details to receive it: {bad_url()}",
    # subtle: no link, social-engineering only
    lambda: f"Good day po, this is from {random.choice(banks)} support. To verify your account, please reply with your full name, card number, and the OTP you received.",
]

# --- Legit templates (label 0), incl. tricky ones with 'account/otp/verify/payment' ---
legit = [
    lambda: f"Thank you for shopping with {random.choice(merchants)}! Your order #{random.randint(10000,99999)} of PHP {amt()} will be delivered on {random.choice(dates)}.",
    lambda: f"Your {random.choice(banks)} OTP is {code()}. Do not share this code with anyone. {random.choice(banks)} will never ask for it.",
    lambda: f"Hi team, tomorrow's standup is moved to {random.choice(times)}. The agenda is in our shared doc. Thanks!",
    lambda: f"Hey {random.choice(names).split()[0]}, are we still on for lunch on {random.choice(dates)}? Let me know what time works.",
    lambda: f"Reminder: your appointment with Dr. {random.choice(names).split()[1]} is on {random.choice(dates)} at {random.choice(times)}. Please arrive 10 minutes early.",
    lambda: f"You spent PHP {amt()} at {random.choice(merchants)} on {random.choice(dates)}. Available balance: PHP {amt()}. - {random.choice(banks)}",
    lambda: f"Your order has shipped via {random.choice(couriers)} and is out for delivery today. Track it in the app.",
    lambda: f"Here's your weekly newsletter from {random.choice(brands)}: 5 tips to stay productive this week.",
    lambda: f"Welcome to {random.choice(services)}! Your subscription is now active. Enjoy unlimited streaming.",
    lambda: f"Hi {random.choice(names).split()[0]}, attached is the report you requested. Let me know if you need any changes.",
    lambda: f"Your payment of PHP {amt()} for your electricity bill has been received. Thank you for paying on time.",
    lambda: f"Class is cancelled today. We'll resume next week. Please review chapters 3 and 4 in advance.",
    # tricky legit: contains 'account'/'password' but benign
    lambda: f"Your {random.choice(services)} account password was changed successfully. If this was you, no action is needed.",
]


def build(templates, label, n):
    rows = []
    for i in range(n):
        rows.append({"content": templates[i % len(templates)](), "actual_label": label})
    return rows


def main():
    data = build(phishing, 1, 100) + build(legit, 0, 100)
    random.shuffle(data)

    with open("ground_truth_200.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "origin", "content", "actual_label", "original_image_path"])
        for idx, row in enumerate(data, start=1):
            origin = "synthetic_phishing" if row["actual_label"] == 1 else "synthetic_legit"
            w.writerow([idx, origin, row["content"], row["actual_label"], ""])

    print(f"Wrote ground_truth_200.csv: {len(data)} rows "
          f"({sum(1 for r in data if r['actual_label']==1)} phishing / "
          f"{sum(1 for r in data if r['actual_label']==0)} legit)")


if __name__ == "__main__":
    main()
