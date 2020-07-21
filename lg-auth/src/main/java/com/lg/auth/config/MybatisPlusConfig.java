package com.lg.auth.config;

import com.baomidou.mybatisplus.core.exceptions.MybatisPlusException;
import com.baomidou.mybatisplus.core.toolkit.StringPool;
import com.baomidou.mybatisplus.extension.plugins.PaginationInterceptor;
import com.baomidou.mybatisplus.extension.plugins.pagination.optimize.JsqlParserCountOptimize;
import com.baomidou.mybatisplus.generator.AutoGenerator;
import com.baomidou.mybatisplus.generator.InjectionConfig;
import com.baomidou.mybatisplus.generator.config.*;
import com.baomidou.mybatisplus.generator.config.po.TableInfo;
import com.baomidou.mybatisplus.generator.config.rules.NamingStrategy;
import com.baomidou.mybatisplus.generator.engine.FreemarkerTemplateEngine;
import org.apache.commons.lang3.StringUtils;
import org.mybatis.spring.annotation.MapperScan;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

@EnableTransactionManagement
@Configuration
@MapperScan("com.lg.auth.mapper")
public class MybatisPlusConfig {

    private Logger logger = LoggerFactory.getLogger(MybatisPlusConfig.class);

    @Bean //分页拦截器
    public PaginationInterceptor paginationInterceptor() {
        PaginationInterceptor paginationInterceptor = new PaginationInterceptor();
        // 设置请求的页面大于最大页后操作， true调回到首页，false 继续请求  默认false
        // paginationInterceptor.setOverflow(false);
        // 设置最大单页限制数量，默认 500 条，-1 不受限制
        // paginationInterceptor.setLimit(500);
        // 开启 count 的 join 优化,只针对部分 left join
        paginationInterceptor.setCountSqlParser(new JsqlParserCountOptimize(true));
        return paginationInterceptor;
    }

    /**
     * 代码生成方法
     *
     * @param args
     */
    public static void main(String[] args) {
        //如果在空项目下创建模块项目，我需要制定模块的名称,否则设置为空
        String moduleName = "permission-api";
//        String moduleName = "";
        // 代码生成器
        AutoGenerator mpg = new AutoGenerator();

        // 全局配置
        GlobalConfig gc = new GlobalConfig();
        String projectPath = System.getProperty("user.dir");
        gc.setOutputDir(projectPath + "/" +moduleName+"/src/main/java");
        //需要修改
        gc.setAuthor("zhanggm");
        gc.setOpen(false);
        mpg.setGlobalConfig(gc);

        // 数据源配置
        //需要修改
        DataSourceConfig dsc = new DataSourceConfig();
        dsc.setUrl("jdbc:mysql://localhost:3306/permission?useUnicode=true&characterEncoding=utf8&serverTimezone=Asia/Shanghai");
        dsc.setDriverName("com.mysql.jdbc.Driver");
        dsc.setUsername("root");
        dsc.setPassword("root");
        mpg.setDataSource(dsc);

        //包配置
        PackageConfig pc = new PackageConfig();
//        pc.setModuleName(scanner("请输入你的包名"));
        //需要修改
        pc.setParent("com.bawei.permission");//你哪个父目录下创建包
        mpg.setPackageInfo(pc);

        //自定义配置
        InjectionConfig cfg = new InjectionConfig() {
            @Override
            public void initMap() {
                // to do nothing
            }
        };

        // 如果模板引擎是 freemarker
        String templatePath = "/templates/mapper.xml.ftl";
        // 如果模板引擎是 velocity
        // String templatePath = "/templates/mapper.xml.vm";

        // 自定义输出配置
        List<FileOutConfig> focList = new ArrayList<>();
        // 自定义配置会被优先输出
        focList.add(new FileOutConfig(templatePath) {
            @Override
            public String outputFile(TableInfo tableInfo) {
                // 自定义输出文件名 ， 如果你 Entity 设置了前后缀、此处注意 xml 的名称会跟着发生变化！！
                return projectPath + "/"+moduleName +"/src/main/resources/mappers/" /*+ pc.getModuleName()
                        + "/"*/ + tableInfo.getEntityName() + "Mapper" + StringPool.DOT_XML;
            }
        });
        cfg.setFileOutConfigList(focList);
        mpg.setCfg(cfg);

        // 配置模板
        TemplateConfig templateConfig = new TemplateConfig();

        // 配置自定义输出模板
        //指定自定义模板路径，注意不要带上.ftl/.vm, 会根据使用的模板引擎自动识别
        // templateConfig.setEntity("templates/entity2.java");
        // templateConfig.setService();
        // templateConfig.setController();

        templateConfig.setXml(null);
        mpg.setTemplate(templateConfig);

        // 策略配置,数据库表配置
        StrategyConfig strategy = new StrategyConfig();
        //数据库表映射到实体的命名策略
        strategy.setNaming(NamingStrategy.underline_to_camel);
        //数据库表字段映射到实体类的命名策略
        strategy.setColumnNaming(NamingStrategy.underline_to_camel);
        //自定义继承entity类，添加这一个会在生成实体类的时候继承entity
        //strategy.setSuperEntityClass("com.wy.testCodeGenerator.entity");
        //实体是否为lombok模型
        strategy.setEntityLombokModel(true);
        //生成@RestController控制器
        strategy.setRestControllerStyle(true);
        //是否继承controller
        // strategy.setSuperControllerClass("com.wy.testCodeGenerator.controller");
//        strategy.setInclude(scanner("表名，多个英文逗号分割").split(","));
        //需要修改
        strategy.setInclude("area","department","employee","menu","position","role","role_menu","user","user_role");
//        strategy.setSuperEntityColumns("id");
        //驼峰转连字符串
        strategy.setControllerMappingHyphenStyle(true);
        //表前缀
        strategy.setTablePrefix("t_");
        mpg.setStrategy(strategy);
        mpg.setTemplateEngine(new FreemarkerTemplateEngine());
        mpg.execute();
    }

    public static String scanner(String someThing) {
        Scanner scanner = new Scanner(System.in);
        StringBuilder help = new StringBuilder();
        help.append("请输入" + someThing + "：");
        System.out.println(help.toString());
        if (scanner.hasNext()) {
            String sc = scanner.next();
            if (StringUtils.isNotEmpty(sc)) {
                return sc;
            }
        }
        throw new MybatisPlusException("请输入正确的" + someThing + "！");
    }
}
