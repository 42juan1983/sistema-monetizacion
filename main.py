"""
Sistema Autónomo de Monetización Digital Escalable (USDT BEP20)
-----------------------------------------------------------------
- Recepción de pagos USDT en red BEP20 a dirección fija (hardcoded)
- Confirmación automática y asignación de acceso premium
- Logging y auditoría de transacciones (tx_hash, monto, timestamp, usuario)
- API REST con FastAPI
- Preparado para despliegue en servicios como Render, Railway o servidor propio
"""

import os
import logging
import datetime
import requests
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Depends, Query
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import uvicorn

# ============== CONFIGURACIÓN GENERAL ==============
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./users.db")
BEP20_RECEIVING_ADDRESS = "0xc6A33a318349a6CeC7d7fd57Bc25d8B6b2346944"  # HARD-CODED - NO MODIFICAR
BEP20_TOKEN_CONTRACT = "0x55d398326f99059fF775485246999027B3197955"  # USDT BEP20
BEP20_MIN_USDT_AMOUNT = 5.0  # Mínimo en USDT
BSCSCAN_API_KEY = os.getenv("")

# ============== LOGS Y ALERTAS ==============
AUDIT_LOG_FILE = "bep20_audit.log"
logging.basicConfig(level=logging.INFO, filename='monetization_system.log')

def alerta_seguridad(mensaje: str):
    logging.critical(f"ALERTA DE SEGURIDAD: {mensaje}")

def log_auditoria(tx_hash: str, amount: float, timestamp: str, username: str):
    """
    Registra cada transacción detectada en archivo append-only.
    """
    log_entry = f"{timestamp} | USER: {username} | TX_HASH: {tx_hash} | AMOUNT: {amount} USDT | WALLET: {BEP20_RECEIVING_ADDRESS}\n"
    with open(AUDIT_LOG_FILE, "a") as f:
        f.write(log_entry)

# ============== BASE DE DATOS Y MODELOS ==============
Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    is_premium = Column(Boolean, default=False)
    joined_at = Column(DateTime, default=datetime.datetime.utcnow)

class Payment(Base):
    __tablename__ = "payments"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer)
    amount = Column(Float)
    method = Column(String)  # 'bep20'
    status = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    reference = Column(String, nullable=True)  # Hash transacción

Base.metadata.create_all(bind=engine)

# ============== FASTAPI APP ==============
app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ============== VERIFICACIÓN DE PAGO BEP20 USDT ==============
def verificar_pago_bep20(tx_hash: str, min_amount: float = BEP20_MIN_USDT_AMOUNT) -> Optional[float]:
    """
    Consulta BscScan para validar que el hash corresponde a un pago de USDT recibido
    en la dirección fija BEP20_RECEIVING_ADDRESS por al menos min_amount USDT.
    Retorna el monto si es válido, None si no lo es.
    """
    try:
        url = (
            f"https://api.bscscan.com/api"
            f"?module=account"
            f"&action=tokentx"
            f"&contractaddress={BEP20_TOKEN_CONTRACT}"
            f"&address={BEP20_RECEIVING_ADDRESS}"
            f"&apikey={BSCSCAN_API_KEY}"
        )
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "1" or "result" not in data:
            return None
        for tx in data["result"]:
            if tx["hash"].lower() == tx_hash.lower() \
                and tx["to"].lower() == BEP20_RECEIVING_ADDRESS.lower():
                amount = float(int(tx["value"]) / (10**18))
                if amount >= min_amount:
                    return amount
        return None
    except Exception as e:
        logging.error(f"Error verificando pago BEP20: {e}")
        return None

# ============== REGISTRO/LOGIN USUARIO Y ACCESO PREMIUM ==============

class UserIn(BaseModel):
    username: str

@app.post("/register")
def register_user(user_in: UserIn, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=user_in.username).first()
    if user:
        return {"msg": "Usuario ya registrado"}
    user = User(username=user_in.username)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"msg": "Registro exitoso", "user_id": user.id}

@app.get("/premium/{username}")
def acceso_premium(username: str, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=username).first()
    if not user:
        raise HTTPException(404, "No encontrado")
    return {"is_premium": user.is_premium}

# ============== PAGO BEP20 USDT ==============

class PagoIn(BaseModel):
    username: str
    metodo: str  # 'bep20'
    amount: float = BEP20_MIN_USDT_AMOUNT

@app.post("/pago")
def iniciar_pago(pago_in: PagoIn, db: Session = Depends(get_db)):
    if BEP20_RECEIVING_ADDRESS != "0xc6A33a318349a6CeC7d7fd57Bc25d8B6b2346944":
        alerta_seguridad("Intento de modificación de la dirección BEP20 detectado.")
        raise HTTPException(403, "Dirección BEP20 no autorizada")
    if pago_in.metodo.lower() != "bep20":
        raise HTTPException(400, "Sólo se acepta método 'bep20'")
    user = db.query(User).filter_by(username=pago_in.username).first()
    if not user:
        raise HTTPException(404, "Usuario no encontrado")
    db.add(Payment(user_id=user.id, amount=pago_in.amount, method="bep20", status="pending"))
    db.commit()
    instrucciones = (
        f"Envíe {pago_in.amount} USDT (BEP20) a la dirección oficial:\n"
        f"{BEP20_RECEIVING_ADDRESS}\n"
        f"Guarde el hash (TXID) para validar su pago."
    )
    return {"payment_instructions": instrucciones, "bep20_address": BEP20_RECEIVING_ADDRESS}

class ConfirmBep20In(BaseModel):
    username: str
    tx_hash: str

@app.post("/confirmar_bep20")
def confirmar_pago_bep20(confirm_in: ConfirmBep20In, db: Session = Depends(get_db)):
    if BEP20_RECEIVING_ADDRESS != "0xc6A33a318349a6CeC7d7fd57Bc25d8B6b2346944":
        alerta_seguridad("Intento de modificación de la dirección BEP20 detectado.")
        raise HTTPException(403, "Dirección BEP20 no autorizada")
    user = db.query(User).filter_by(username=confirm_in.username).first()
    if not user:
        raise HTTPException(404, "Usuario no encontrado")
    amount = verificar_pago_bep20(confirm_in.tx_hash)
    if amount is not None:
        user.is_premium = True
        payment = Payment(
            user_id=user.id, amount=amount, method="bep20",
            status="success", reference=confirm_in.tx_hash
        )
        db.add(payment)
        db.commit()
        log_auditoria(confirm_in.tx_hash, amount, datetime.datetime.utcnow().isoformat(), confirm_in.username)
        logging.info(f"Pago BEP20 confirmado: usuario={confirm_in.username}, hash={confirm_in.tx_hash}, amount={amount}")
        return {"msg": f"Pago BEP20 confirmado ({amount} USDT) y acceso premium activado"}
    else:
        logging.warning(f"Fallo verificación BEP20: usuario={confirm_in.username}, hash={confirm_in.tx_hash}")
        return {"msg": "Pago no verificado aún. Asegúrese de enviar el monto mínimo y que la transacción haya sido confirmada en blockchain."}

# ============== REPORTES DE AUDITORÍA Y TRAZABILIDAD ==============

@app.get("/audit/wallet")
def reporte_wallet(address: str = Query(..., description="Dirección BEP20 (debe ser la oficial)")):
    if address.lower() != BEP20_RECEIVING_ADDRESS.lower():
        raise HTTPException(403, "Sólo se puede consultar la wallet oficial")
    results = []
    if not os.path.exists(AUDIT_LOG_FILE):
        return {"transactions": results}
    with open(AUDIT_LOG_FILE, "r") as f:
        for line in f:
            if BEP20_RECEIVING_ADDRESS.lower() in line.lower():
                results.append(line.strip())
    return {"transactions": results}

@app.get("/audit/user")
def reporte_usuario(username: str = Query(..., description="Username a auditar")):
    results = []
    if not os.path.exists(AUDIT_LOG_FILE):
        return {"transactions": results}
    with open(AUDIT_LOG_FILE, "r") as f:
        for line in f:
            if f"USER: {username} " in line:
                results.append(line.strip())
    return {"transactions": results}

# ============== EJECUCIÓN REMOTA ==============
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 7860)))

"""
Notas:
- Reemplaza 'YOUR_BSCSCAN_API_KEY' por tu API Key real de BscScan.
- El archivo bep20_audit.log se genera automáticamente e incluye todos los registros relevantes para auditoría.
- El endpoint /confirmar_bep20 activa premium tras verificación automática en blockchain.
- Listo para despliegue en Render, Railway, etc.
"""
