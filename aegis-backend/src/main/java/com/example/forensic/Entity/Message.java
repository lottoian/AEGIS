package com.example.forensic.Entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.*;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class Message {

    private String content;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime deviceTimestamp;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime serverTimestamp;

    /** serverTimestamp가 캐시 기반 추정값이면 true */
    private boolean estimatedServerTimestamp;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime transmissionTimestamp;

    /** 기존 호환용 생성자 */
    public Message(String content, LocalDateTime deviceTimestamp, LocalDateTime serverTimestamp) {
        this.content = content;
        this.deviceTimestamp = deviceTimestamp;
        this.serverTimestamp = serverTimestamp;
        this.estimatedServerTimestamp = false;
        this.transmissionTimestamp = null;
    }
}
