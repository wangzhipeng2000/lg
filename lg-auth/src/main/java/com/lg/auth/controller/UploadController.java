package com.lg.auth.controller;

import com.lg.common.pojo.ResponseResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/file/")
public class UploadController {

    @Value("${file.path}")
    private String filePath;

    @Value("${file.domain}")
    private String fileDomain;

    @PostMapping("upload")
    public ResponseResult upload(@RequestParam("file") MultipartFile file){
        //返回的结果
        Map<String,Object> imgInfo = new HashMap<>();
        //文件名称
        String originalFilename = file.getOriginalFilename();
        String extName = originalFilename.substring(originalFilename.lastIndexOf("."));
        String fileName = UUID.randomUUID()+extName;
        //保存图片
        File saveFile = new File(filePath,fileName);
        try {
            file.transferTo(saveFile);
            imgInfo.put("imgUrl",fileDomain+fileName);
            imgInfo.put("fileName",fileName);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return ResponseResult.success(imgInfo);
    }
}
