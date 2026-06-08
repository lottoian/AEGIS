package com.example.forensic.config;

// 암호화/복호화는 LogService에서 서비스 레벨로 직접 처리.
// Spring Data MongoDB 이벤트 리스너(onBeforeSave)는 Document 변환 후 실행되어
// 엔티티 수정이 실제 저장에 반영되지 않는 문제가 있어 제거.
