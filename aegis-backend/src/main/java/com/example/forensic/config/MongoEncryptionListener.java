package com.example.forensic.config;

import com.example.forensic.Entity.Log;
import com.example.forensic.Entity.Message;
import org.springframework.data.mongodb.core.mapping.event.AbstractMongoEventListener;
import org.springframework.data.mongodb.core.mapping.event.AfterConvertEvent;
import org.springframework.data.mongodb.core.mapping.event.BeforeSaveEvent;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * MongoDB 저장 전 Message.content 암호화, 로드 후 복호화.
 * Log 도큐먼트의 message[].content 필드에만 적용 — deviceId 등 쿼리 키는 평문 유지.
 */
@Component
public class MongoEncryptionListener extends AbstractMongoEventListener<Log> {

    private final FieldEncryptionConverter enc;

    public MongoEncryptionListener(FieldEncryptionConverter enc) {
        this.enc = enc;
    }

    /** 저장 직전: content 암호화 */
    @Override
    public void onBeforeSave(BeforeSaveEvent<Log> event) {
        encryptMessages(event.getSource().getMessage());
    }

    /** 로드 후 엔티티 변환 완료 시점: content 복호화 */
    @Override
    public void onAfterConvert(AfterConvertEvent<Log> event) {
        decryptMessages(event.getSource().getMessage());
    }

    private void encryptMessages(List<Message> messages) {
        if (messages == null) return;
        for (Message msg : messages) {
            if (msg.getContent() != null && !looksEncrypted(msg.getContent())) {
                msg.setContent(enc.encrypt(msg.getContent()));
            }
        }
    }

    private void decryptMessages(List<Message> messages) {
        if (messages == null) return;
        for (Message msg : messages) {
            if (msg.getContent() != null) {
                msg.setContent(enc.decrypt(msg.getContent()));
            }
        }
    }

    /**
     * 이미 암호화된 값인지 휴리스틱 판별.
     * FieldEncryptionConverter는 IV(12B) + ciphertext를 Base64 인코딩하므로
     * 최소 16자 이상의 순수 Base64 문자열이면 암호화된 것으로 간주.
     * 일반 로그 메시지는 공백/한글 등 non-Base64 문자를 포함하므로 오탐 가능성 낮음.
     */
    private boolean looksEncrypted(String s) {
        return s.length() >= 24 && s.matches("[A-Za-z0-9+/]+=*");
    }
}
