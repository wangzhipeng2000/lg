package com.lg.user.service;

import com.lg.user.dao.UserDao;
import com.lg.user.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;
import java.util.ArrayList;
import java.util.List;

/**
 * TODO
 *
 * @author Zgm
 * @version 1.0
 * @date 2020/7/3 0003 15:26
 */
@Service
public class UserService {

    @Autowired
    private UserDao userDao;

    /**
     * 用户的分页查询接口
     * @param user
     * @param current
     * @param size
     * @return
     */
    public Page<User> getPageInfo(User user, Integer current, Integer size) {
        Specification<User> specification = new Specification<User>() {
            @Override
            public Predicate toPredicate(Root<User> root, CriteriaQuery<?> criteriaQuery, CriteriaBuilder criteriaBuilder) {
                List<Predicate> predicates = new ArrayList<>();

                return criteriaBuilder.and(predicates.toArray(new Predicate[predicates.size()]));
            }
        };
        Pageable pageable = PageRequest.of(current-1,size, Sort.Direction.DESC,"id");
        return  userDao.findAll(specification,pageable);
    }
}
